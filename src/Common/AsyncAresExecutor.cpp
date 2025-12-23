#include <Common/AsyncAresExecutor.h>

#include <base/defines.h>
#include <Common/Exception.h>
#include <Common/EPoll.h>

#include <ares_nameser.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <algorithm>
#include <concepts>
#include <future>
#include <string>
#include <vector>
#include <type_traits>

namespace {

constexpr uint32_t MIN_TTL = 60u;
constexpr uint32_t MAX_TTL = 86400u;

struct SocketAddressWithPriority
{
    /// socket_address is just a hostname with a port number, i.e: example.com:1234
    std::string socket_address;
    uint16_t priority;
};

struct SRVRecordOutput
{
    std::vector<SocketAddressWithPriority> socket_addresses_with_priority;
    uint32_t min_ttl;
};

struct ARecordOutput
{
    std::vector<std::string> ipv4_addresses;
    uint32_t min_ttl;
};

struct AAAARecordOutput
{
    std::vector<std::string> ipv6_addresses;
    uint32_t min_ttl;
};

template <typename T>
struct OutputWithBinarySemaphore
{
    std::binary_semaphore sem{0};
    T output;
};

enum class ErrorCode : std::uint8_t {
    /// Ares query errors
    AresQueryNetworkParamsError,        /// (Windows) Failed to retrieve network parameters.
    AresQueryInvalidAddressFamily,      /// The requested address family (IPv4/IPv6) is not supported.
    AresQueryInvalidFlags,              /// Invalid flags passed to the library function.
    AresQueryInvalidHints,              /// Invalid hints provided for address lookups.
    AresQueryInvalidName,               /// The provided domain name contains illegal characters.
    AresQueryInvalidQuery,              /// The DNS query structure is malformed.
    AresQueryInvalidResponse,           /// Server sent a malformed or unparseable response.
    AresQueryInvalidString,             /// A malformed string was provided to the library.
    AresQueryCancelled,                 /// The query was explicitly cancelled by the user.
    AresQueryConnectionRefused,         /// Could not connect to the DNS server.
    AresQueryChannelDestroyed,          /// The channel was destroyed while the query was pending.
    AresQueryConfigurationFileError,    /// Error reading configuration files (e. g. , resolv. conf).
    AresQueryFormError,                 /// Server claimed the query was formatted incorrectly.
    AresQueryLoadLibraryError,          /// (Windows) Failed to load iphlpapi. dll.
    AresQueryNoData,                    /// Domain exists, but has no records of the requested type.
    AresQueryOutOfMemory,               /// Memory allocation failed.
    AresQueryNoName,                    /// Hostname could not be resolved (internal/system lookup).
    AresQueryNotFound,                  /// Domain name not found (NXDOMAIN).
    AresQueryNotImplemented,            /// Server does not support the requested operation.
    AresQueryNotInitialized,            /// The library was not properly initialized.
    AresQueryNotSpecial,                /// Name is not a "special" name (used in specific lookup types).
    AresQueryEndOfFile,                 /// Unexpected end of file/stream during TCP connection.
    AresQueryRefused,                   /// The DNS server refused the query (e. g. , ACL/Policy).
    AresQueryServerFailure,             /// DNS server reported a general internal failure.
    AresQueryTimeout,                   /// No response received within the timeout period.
    AresQueryUnknown,

    AresParseSrvReplyFailed,            /// Failed to parse SRV record reply
    AresParseAFailed,                   /// Failed to parse A record reply
    AresParseAAAAFailed,                /// Failed to parse AAAA record reply

    ClientCallbackTimeout,
};

enum class QueryType { SRV_RECORD, A_RECORD, AAAA_RECORD, PTR_RECORD };

template <QueryType Q>
consteval ares_dns_rec_type_t get_ares_rec_type() {
    if constexpr (Q == QueryType::SRV_RECORD)       return ARES_REC_TYPE_SRV;
    else if constexpr (Q == QueryType::A_RECORD)    return ARES_REC_TYPE_A;
    else if constexpr (Q == QueryType::AAAA_RECORD) return ARES_REC_TYPE_AAAA;
    else static_assert(Q != Q, "Unsupported template QueryType provided to get_ares_rec_type()");
}

template <QueryType Q>
consteval auto get_output_type_tag() {
    if constexpr (Q == QueryType::SRV_RECORD)  return std::type_identity<SRVRecordOutput>{};
    else if constexpr (Q == QueryType::A_RECORD)    return std::type_identity<ARecordOutput>{};
    else if constexpr (Q == QueryType::AAAA_RECORD) return std::type_identity<AAAARecordOutput>{};
    else static_assert(Q != Q, "Unsupported template QueryType provided to get_output_type_tag()");
}

/// Forward declarations of our handlers for responses
std::variant<ErrorCode, SRVRecordOutput> handleResponseSRVRecord(unsigned char * abuf, int alen);
std::variant<ErrorCode, ARecordOutput> handleResponseARecord(unsigned char * abuf, int alen);
std::variant<ErrorCode, AAAARecordOutput> handleResponseAAAARecord(unsigned char * abuf, int alen);
std::variant<ErrorCode, PTRRecordOutput> handleResponsePTRRecord(unsigned char * abuf, int alen);
template <QueryType Q>
consteval auto get_handler() {
    if constexpr (Q == QueryType::SRV_RECORD)       return &handleResponseSRVRecord;
    else if constexpr (Q == QueryType::A_RECORD)    return &handleResponseARecord;
    else if constexpr (Q == QueryType::AAAA_RECORD) return &handleResponseAAAARecord;
    else if constexpr (Q == QueryType::PTR_RECORD)  return &handleResponsePTRRecord;
    else static_assert(Q != Q, "Unsupported template QueryType provided to get_handler()");
}

constexpr ErrorCode ares_status_to_error_code(int status) noexcept
{
    switch (status)
    {
        case ARES_EADDRGETNETWORKPARAMS: return ErrorCode::AresQueryNetworkParamsError;     /// (Windows) Failed to retrieve network parameters.
        case ARES_EBADFAMILY:            return ErrorCode::AresQueryInvalidAddressFamily;   /// The requested address family (IPv4/IPv6) is not supported.
        case ARES_EBADFLAGS:             return ErrorCode::AresQueryInvalidFlags;           /// Invalid flags passed to the library function.
        case ARES_EBADHINTS:             return ErrorCode::AresQueryInvalidHints;           /// Invalid hints provided for address lookups.
        case ARES_EBADNAME:              return ErrorCode::AresQueryInvalidName;            /// The provided domain name contains illegal characters.
        case ARES_EBADQUERY:             return ErrorCode::AresQueryInvalidQuery;           /// The DNS query structure is malformed.
        case ARES_EBADRESP:              return ErrorCode::AresQueryInvalidResponse;        /// Server sent a malformed or unparseable response.
        case ARES_EBADSTR:               return ErrorCode::AresQueryInvalidString;          /// A malformed string was provided to the library.
        case ARES_ECANCELLED:            return ErrorCode::AresQueryCancelled;              /// The query was explicitly cancelled by the user.
        case ARES_ECONNREFUSED:          return ErrorCode::AresQueryConnectionRefused;      /// Could not connect to the DNS server.
        case ARES_EDESTRUCTION:          return ErrorCode::AresQueryChannelDestroyed;       /// The channel was destroyed while the query was pending.
        case ARES_EFILE:                 return ErrorCode::AresQueryConfigurationFileError; /// Error reading configuration files (e. g. , resolv. conf).
        case ARES_EFORMERR:              return ErrorCode::AresQueryFormError;              /// Server claimed the query was formatted incorrectly.
        case ARES_ELOADIPHLPAPI:         return ErrorCode::AresQueryLoadLibraryError;       /// (Windows) Failed to load iphlpapi. dll.
        case ARES_ENODATA:               return ErrorCode::AresQueryNoData;                 /// Domain exists, but has no records of the requested type.
        case ARES_ENOMEM:                return ErrorCode::AresQueryOutOfMemory;            /// Memory allocation failed.
        case ARES_ENONAME:               return ErrorCode::AresQueryNoName;                 /// Hostname could not be resolved (internal/system lookup).
        case ARES_ENOTFOUND:             return ErrorCode::AresQueryNotFound;               /// Domain name not found (NXDOMAIN).
        case ARES_ENOTIMP:               return ErrorCode::AresQueryNotImplemented;         /// Server does not support the requested operation.
        case ARES_ENOTINITIALIZED:       return ErrorCode::AresQueryNotInitialized;         /// The library was not properly initialized.
        case ARES_ENOTSPECIAL:           return ErrorCode::AresQueryNotSpecial;             /// Name is not a "special" name (used in specific lookup types).
        case ARES_EOF:                   return ErrorCode::AresQueryEndOfFile;              /// Unexpected end of file/stream during TCP connection.
        case ARES_EREFUSED:              return ErrorCode::AresQueryRefused;                /// The DNS server refused the query (e. g. , ACL/Policy).
        case ARES_ESERVFAIL:             return ErrorCode::AresQueryServerFailure;          /// DNS server reported a general internal failure.
        case ARES_ETIMEOUT:              return ErrorCode::AresQueryTimeout;                /// No response received within the timeout period.
        default:                         return ErrorCode::AresQueryUnknown;
    }
}

std::variant<ErrorCode, SRVRecordOutput> HandleResponseSRV(unsigned char * abuf, int alen)
{

    struct ares_srv_reply * reply = nullptr;
    int parse_status = ares_parse_srv_reply(abuf, alen, &reply);
    if (parse_status != ARES_SUCCESS || !reply) [[unlikely]]
        return ErrorCode::AresParseSrvReplyFailed;

    SRVRecordOutput output;

    /// Extract minimum TTL, clamped to MIN_TTL and MAX_TTL
    output.min_ttl = MIN_TTL; 
    ns_msg msg;
    if (ns_initparse(abuf, alen, &msg) == 0) [[likely]]
    {
        const auto count = ns_msg_count(msg, ns_s_an);
        for (auto i = 0; i < count; ++i)
        {
            ns_rr rr;
            if (ns_parserr(&msg, ns_s_an, i, &rr) == 0) [[likely]]
            {
                output.min_ttl = std::min(output.min_ttl, static_cast<uint32_t>(ns_rr_ttl(rr)));
            }
        }
    }
    output.min_ttl = std::clamp(output.min_ttl, MIN_TTL, MAX_TTL);

    /// Extract socket addresses with priority
    std::vector<SocketAddressWithPriority>& output_vec = output.socket_addresses_with_priority;
    for (auto * curr = reply; curr != nullptr; curr = curr->next)
    {
        if (const char * host = curr->host; host && *host) [[likely]]
        {
            output_vec.emplace_back(SocketAddressWithPriority{
                std::string(host) + ":" + std::to_string(curr->port),
                static_cast<uint16_t>(curr->priority)
            });
        }
    }

    ares_free_data(reply);

    if (output_vec.empty()) [[unlikely]]
        return output;

    std::sort(
        output_vec.begin(), output_vec.end(),
        [](const SocketAddressWithPriority & a, const SocketAddressWithPriority & b)
        {
            return a.priority < b.priority;
        }
    );

    return output;
}

ALWAYS_INLINE void aresQuerySRVRecord(ares_channel channel, const char * name, ares_callback cb, void * arg)
{
    ares_query(channel, name, ARES_CLASS_IN, ARES_REC_TYPE_SRV, cb, arg);
}

ALWAYS_INLINE void aresQueryARecord(ares_channel channel, const char * name, ares_callback cb, void * arg)
{
    ares_query(channel, name, ARES_CLASS_IN, ARES_REC_TYPE_A, cb, arg);
}

ALWAYS_INLINE void aresQueryAAAARecord(ares_channel channel, const char * name, ares_callback cb, void * arg)
{
    ares_query(channel, name, ARES_CLASS_IN, ARES_REC_TYPE_AAAA, cb, arg);
}

ALWAYS_INLINE void aresQueryPTRRecordFromIPv4(ares_channel channel, const std::string& ip_address, ares_callback cb, void * arg)
{
    unsigned char buf[128];
    std::string query_name;

    if (inet_pton(AF_INET, ip_address.c_str(), buf) == 1)
    {
        family = AF_INET;
        query_name = std::format(
            "{}.{}.{}.{}.in-addr.arpa", 
            buf[3], buf[2], buf[1], buf[0]
        );
    } 
    else if (inet_pton(AF_INET6, ip_address.c_str(), buf) == 1)
    {
        family = AF_INET6;
        // IPv6 requires reversing every nibble (4 bits)
        // Example: 2001:db8... -> ...8.b.d.0.1.0.0.2.ip6.arpa
        std::string nibbles;
        for (int i = 15; i >= 0; --i) {
            nibbles += std::format("{:x}.{:x}.", buf[i] & 0x0F, (buf[i] >> 4) & 0x0F);
        }
        query_name = nibbles + "ip6.arpa";
    } 
    else
        throw Exception();
        throw Exception(ErrorCodes::INVALID_IP_ADDRESS_FORMAT, "Invalid I.P address format: {}", ip_str);

    ares_query(channel, query_name.c_str(), ARES_CLASS_IN, ARES_REC_TYPE_PTR, cb, arg);
}

template <QueryType Q> 
auto resolveBlocking(const std::string& input, const uint32_t timeout_ms)
{
    /// Find out the result type of our handler before invoking it
    using ResultType = std::invoke_result_t<decltype(get_handler<Q>()), unsigned char *, int>;

    using BridgeType = OutputWithBinarySemaphore<ResultType>;
    auto bridge_ptr_shared = std::make_shared<BridgeType>();

    /// Keeps the object inside bridge_ptr_shared alive even if callback happens after this function goes out of scope
    /// Will not leak memory as callbacks are guaranteed with c-ares as long as we ares_destroy() the ares channel on shutdown
    auto bridge_ptr_callback = std::make_unique<std::shared_ptr<BridgeType>>(bridge_ptr_shared);

    auto query_callback = [](void * arg, int status, int /*timeouts*/, unsigned char * abuf, int alen)
    {
        auto bridge_ptr = std::unique_ptr<std::shared_ptr<BridgeType>>(
            static_cast<std::shared_ptr<BridgeType> *>(arg)
        );
        auto& bridge = **bridge_ptr;

        if (status != ARES_SUCCESS) [[unlikely]]
        {
            bridge.output = ares_status_to_error_code(status);
        }
        else
        {
            constexpr auto handler = get_handler<Q>();
            bridge.output = handler(abuf, alen);
        }

        bridge.sem.release(); /// Signal our callback as completed
    };

    constexpr auto ares_rec_type = get_ares_rec_type<Q>();
    ares_query(channel, service_record.c_str(), ARES_CLASS_IN, ares_rec_type, query_callback, bridge_ptr_callback.release());

    if (bridge_ptr_shared->sem.try_acquire_for(std::chrono::milliseconds(timeout_ms)))
    {
        return bridge_ptr_shared->output;
    }

    return ResultType{ErrorCode::ClientCallbackTimeout};
}
    
    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (ares_inet_pton(AF_INET, ip_str.c_str(), &ipv4) == 1)
        ares_gethostbyaddr(channel, &ipv4, sizeof(ipv4), AF_INET, cb, user_data);
    else if (ares_inet_pton(AF_INET6, ip_str.c_str(), &ipv6) == 1)
        ares_gethostbyaddr(channel, &ipv6, sizeof(ipv6), AF_INET6, cb, user_data);
    else
        throw Exception(ErrorCodes::INVALID_IP_ADDRESS_FORMAT, "Invalid I.P address format: {}", ip_str);



}

namespace DB {



namespace ErrorCodes
{
extern const int FAILED_SETUP;
extern const int INVALID_IP_ADDRESS_FORMAT;
}

/// Public methods
AsyncAresExecutor& AsyncAresExecutor::instance()
{
    static AsyncAresExecutor instance;
    return instance;
}





void AsyncAresExecutor::shutdown()
{
    if (is_shutdown_called.exchange(true))
        return;

    if (background_thread && background_thread->joinable())
        background_thread->join();

    if (channel)
    {
        ares_destroy(channel);
        channel = nullptr;
    }
}

/// Private methods
AsyncAresExecutor::AsyncAresExecutor()
{
    /// Only use this class to init the ares library
    /// Do not init ares library multiple times within a program
    if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS)
        throw Exception(ErrorCodes::FAILED_SETUP, "Failed to initialize the c-ares library");

    if (ares_init(&channel) != ARES_SUCCESS)
    {
        ares_library_cleanup();
        throw Exception(ErrorCodes::FAILED_SETUP, "Failed to initialize the c-ares channel");
    }

    background_thread.emplace([] { loop(); });
}

AsyncAresExecutor::~AsyncAresExecutor()
{
    shutdown();
    ares_library_cleanup();
}

void AsyncAresExecutor::loop()
{
    while (true) {
        ares_socket_t sockets[ARES_GETSOCK_MAXNUM];
        int bitmask = ares_getsock(channel, sockets, ARES_GETSOCK_MAXNUM);
        
        // If bitmask is 0, no more pending DNS queries
        if (bitmask == 0) break; 

        struct pollfd pfd[ARES_GETSOCK_MAXNUM];
        int num_fds = 0;

        for (int i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
            pfd[num_fds].fd = sockets[i];
            pfd[num_fds].events = 0;
            pfd[num_fds].revents = 0;

            if (ARES_GETSOCK_READABLE(bitmask, i)) pfd[num_fds].events |= POLLIN;
            if (ARES_GETSOCK_WRITABLE(bitmask, i)) pfd[num_fds].events |= POLLOUT;
            
            if (pfd[num_fds].events != 0) num_fds++;
        }

        // Get the timeout recommended by c-ares (how long to wait for a response)
        struct timeval tvptr;
        struct timeval *tv = ares_timeout(channel, nullptr, &tvptr);
        int timeout_ms = (tv->tv_sec * 1000) + (tv->tv_usec / 1000);

        int ready = poll(pfd, num_fds, timeout_ms);
        
        if (ready < 0) {
            perror("poll");
            break;
        }

        if (ready == 0) {
            // Timeout reached, let c-ares handle retransmissions
            ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        } else {
            // Sockets are ready, process them
            for (int i = 0; i < num_fds; i++) {
                ares_process_fd(channel, 
                    (pfd[i].revents & POLLIN) ? pfd[i].fd : ARES_SOCKET_BAD,
                    (pfd[i].revents & POLLOUT) ? pfd[i].fd : ARES_SOCKET_BAD);
            }
        }
    }
    while (!is_shutdown_called.load())
    {
    // DNS Refresh Logic
    
    // Sleep/Wait logic
    std::this_thread::sleep_for(std::chrono::seconds(60));
    }
}

}
