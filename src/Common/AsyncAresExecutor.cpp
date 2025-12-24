#include <Common/AsyncAresExecutor.h>

#include <base/defines.h>
#include <Common/Exception.h>
#include <Common/EPoll.h>

#include <ares_nameser.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <magic_enum.hpp>

#include <algorithm>
#include <concepts>
#include <future>
#include <string>
#include <string_view>
#include <vector>
#include <type_traits>
#include <variant>
#include <mutex>

namespace DB {

namespace ErrorCodes {
    extern const int INVALID_IP_ADDRESS_FORMAT;
    extern const int EXTERNAL_LIBRARY_ERROR;
    extern const int TIMEOUT_EXCEEDED;
}

}

namespace {

constexpr uint32_t MIN_TTL = 60u;
constexpr uint32_t MAX_TTL = 86400u;
std::mutex g_query_mutex;

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
    AresQueryUnknown,                   /// Unknown ares query error

    AresParseSrvReplyFailed,            /// Failed to parse SRV record reply
    AresParseAFailed,                   /// Failed to parse A record reply
    AresParseAAAAFailed,                /// Failed to parse AAAA record reply
    AresParsePTRFailed,                 /// Failed to parse PTR record reply

    ClientCallbackTimeout,
};

enum class QueryType { SRV_RECORD, A_RECORD, AAAA_RECORD, PTR_RECORD };

template <typename T>
concept IsRecordOutput = (
    std::is_same_v<T, SRVRecordOutput> ||
    std::is_same_v<T, ARecordOutput> ||
    std::is_same_v<T, AAAARecordOutput> ||
    std::is_same_v<T, PTRRecordOutput>
);

template <QueryType Q>
consteval auto get_output_type_tag() {
    if constexpr (Q == QueryType::SRV_RECORD)       return std::type_identity<SRVRecordOutput>{};
    else if constexpr (Q == QueryType::A_RECORD)    return std::type_identity<ARecordOutput>{};
    else if constexpr (Q == QueryType::AAAA_RECORD) return std::type_identity<AAAARecordOutput>{};
    else if constexpr (Q == QueryType::PTR_RECORD)  return std::type_identity<PTRRecordOutput>{};
    else static_assert(Q != Q, "Unsupported template QueryType provided to get_output_type_tag()");
}

/// Forward declarations of our handlers for responses
/// Handlers may not throw exceptions as they are invoked by c-ares, a C library
std::variant<ErrorCode, SRVRecordOutput> handleResponseSRVRecord(unsigned char * abuf, int alen) noexcept;
std::variant<ErrorCode, ARecordOutput> handleResponseARecord(unsigned char * abuf, int alen) noexcept;
std::variant<ErrorCode, AAAARecordOutput> handleResponseAAAARecord(unsigned char * abuf, int alen) noexcept;
std::variant<ErrorCode, PTRRecordOutput> handleResponsePTRRecord(unsigned char * abuf, int alen) noexcept;
template <QueryType Q>
consteval auto get_handler() {
    if constexpr (Q == QueryType::SRV_RECORD)       return &handleResponseSRVRecord;
    else if constexpr (Q == QueryType::A_RECORD)    return &handleResponseARecord;
    else if constexpr (Q == QueryType::AAAA_RECORD) return &handleResponseAAAARecord;
    else if constexpr (Q == QueryType::PTR_RECORD)  return &handleResponsePTRRecord;
    else static_assert(Q != Q, "Unsupported template QueryType provided to get_handler()");
}

/// Forward declarations of our customized ares query functions
void aresQuerySRVRecord(ares_channel channel, const char * name, ares_callback cb, void * arg);
void aresQueryARecord(ares_channel channel, const char * name, ares_callback cb, void * arg);
void aresQueryAAAARecord(ares_channel channel, const char * name, ares_callback cb, void * arg);
void aresQueryPTRRecord(ares_channel channel, const char * name, ares_callback cb, void * arg);
template <QueryType Q>
consteval auto get_query_function() {
    if constexpr (Q == QueryType::SRV_RECORD)       return &aresQuerySRVRecord;
    else if constexpr (Q == QueryType::A_RECORD)    return &aresQueryARecord;
    else if constexpr (Q == QueryType::AAAA_RECORD) return &aresQueryAAAARecord;
    else if constexpr (Q == QueryType::PTR_RECORD)  return &aresQueryPTRRecord;
    else static_assert(Q != Q, "Unsupported template QueryType provided to get_query_function()");
}

constexpr ErrorCode ares_status_to_error_code(int status) noexcept
{
    switch (status)
    {
        case ARES_EADDRGETNETWORKPARAMS: return ErrorCode::AresQueryNetworkParamsError;
        case ARES_EBADFAMILY:            return ErrorCode::AresQueryInvalidAddressFamily;
        case ARES_EBADFLAGS:             return ErrorCode::AresQueryInvalidFlags;
        case ARES_EBADHINTS:             return ErrorCode::AresQueryInvalidHints;
        case ARES_EBADNAME:              return ErrorCode::AresQueryInvalidName;
        case ARES_EBADQUERY:             return ErrorCode::AresQueryInvalidQuery;
        case ARES_EBADRESP:              return ErrorCode::AresQueryInvalidResponse;
        case ARES_EBADSTR:               return ErrorCode::AresQueryInvalidString;
        case ARES_ECANCELLED:            return ErrorCode::AresQueryCancelled;
        case ARES_ECONNREFUSED:          return ErrorCode::AresQueryConnectionRefused;
        case ARES_EDESTRUCTION:          return ErrorCode::AresQueryChannelDestroyed;
        case ARES_EFILE:                 return ErrorCode::AresQueryConfigurationFileError;
        case ARES_EFORMERR:              return ErrorCode::AresQueryFormError;
        case ARES_ELOADIPHLPAPI:         return ErrorCode::AresQueryLoadLibraryError;
        case ARES_ENODATA:               return ErrorCode::AresQueryNoData;  
        case ARES_ENOMEM:                return ErrorCode::AresQueryOutOfMemory;   
        case ARES_ENONAME:               return ErrorCode::AresQueryNoName; 
        case ARES_ENOTFOUND:             return ErrorCode::AresQueryNotFound;  
        case ARES_ENOTIMP:               return ErrorCode::AresQueryNotImplemented;
        case ARES_ENOTINITIALIZED:       return ErrorCode::AresQueryNotInitialized;
        case ARES_ENOTSPECIAL:           return ErrorCode::AresQueryNotSpecial;
        case ARES_EOF:                   return ErrorCode::AresQueryEndOfFile;  
        case ARES_EREFUSED:              return ErrorCode::AresQueryRefused;
        case ARES_ESERVFAIL:             return ErrorCode::AresQueryServerFailure;
        case ARES_ETIMEOUT:              return ErrorCode::AresQueryTimeout;
        default:                         return ErrorCode::AresQueryUnknown;
    }
}

std::variant<ErrorCode, SRVRecordOutput> HandleResponseSRV(unsigned char * abuf, int alen) noexcept
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

ALWAYS_INLINE int aresQuerySRVRecord(ares_channel channel, const char * name, ares_callback cb, void * arg)
{
    {
        std::lock_guard<std::mutex> lock(g_query_mutex);
        return ares_query(channel, name, ARES_CLASS_IN, ARES_REC_TYPE_SRV, cb, arg);
    }
}

ALWAYS_INLINE int aresQueryARecord(ares_channel channel, const char * name, ares_callback cb, void * arg)
{
    {
        std::lock_guard<std::mutex> lock(g_query_mutex);
        return ares_query(channel, name, ARES_CLASS_IN, ARES_REC_TYPE_A, cb, arg);
    }
}

ALWAYS_INLINE int aresQueryAAAARecord(ares_channel channel, const char * name, ares_callback cb, void * arg)
{
    {
        std::lock_guard<std::mutex> lock(g_query_mutex);
        return ares_query(channel, name, ARES_CLASS_IN, ARES_REC_TYPE_AAAA, cb, arg);
    }
}

ALWAYS_INLINE int aresQueryPTRRecord(ares_channel channel, const std::string& ip_address, ares_callback cb, void * arg)
{
    unsigned char buf[16];
    std::string formatted_address;

    if (inet_pton(AF_INET, ip_address.c_str(), buf) == 1)
    {
        formatted_address.reserve(28);
        std::format_to(
            std::back_inserter(formatted_address),
            "{}.{}.{}.{}.in-addr.arpa", 
            buf[3], buf[2], buf[1], buf[0]
        );
    }
    else if (inet_pton(AF_INET6, ip_address.c_str(), buf) == 1)
    {
        /// IPv6 requires reversing every nibble (4 bits)
        /// Shorter example: 2001:0db8 -> 8.b.d.0.1.0.0.2.ip6.arpa
        std::string nibbles;
        nibbles.reserve(64);
        formatted_address.reserve(72);
        for (size_t i = 0; i < 16; ++i)
        {
            const unsigned char current_byte = buf[15 - i]; /// 15 - i so we loop from the other end
            const unsigned char low_nibble = current_byte & 0x0F;
            const unsigned char high_nibble = (current_byte >> 4) & 0x0F;
            nibbles += std::format("{:x}.{:x}.", low_nibble, high_nibble);
        }

        formatted_address = nibbles + "ip6.arpa";
    }
    else
    {
        throw Exception(DB::ErrorCodes::INVALID_IP_ADDRESS_FORMAT, "aresQueryPTRRecord(): Invalid I.P address format: {}", ip_address);
    }

    {
        std::lock_guard<std::mutex> lock(g_query_mutex);
        return ares_query(channel, formatted_address.c_str(), ARES_CLASS_IN, ARES_REC_TYPE_PTR, cb, arg);
    }
}

template <QueryType Q> 
auto resolveBlocking(ares_channel channel, const std::string& input, const uint32_t timeout_ms)
{
    /// Find out the result type of our handler before invoking it
    using ResultType = std::invoke_result_t<decltype(get_handler<Q>()), unsigned char *, int>;

    /// Compile-time static assertions to prevent wrong usage of function
    using VariantErrorType = std::variant_alternative_t<0, ResultType>;
    static_assert(std::is_same_v<VariantErrorType, ErrorCode>, "Variant error type mismatch in resolveBlocking()");
    using VariantOutputType = std::variant_alternative_t<1, ResultType>;
    static_assert(IsRecordOutput<VariantOutputType>, "Variant output type mismatch in resolveBlocking()");

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

    constexpr auto query_func = get_query_function<Q>();
    int status = query_func(channel, input.c_str(), query_callback, bridge_ptr_callback.get());
    if (status != ARES_SUCCESS) [[unlikely]]
        throw Exception(DB::ErrorCodes::EXTERNAL_LIBRARY_ERROR, "resolveBlocking(): Failed to enqueue query: {}", ares_strerror(status));
    else
        bridge_ptr_callback.release();

    if (bridge_ptr_shared->sem.try_acquire_for(std::chrono::milliseconds(timeout_ms)))
    {
        if (const auto * val = std::get_if<VariantErrorType>(&bridge_ptr_shared->output))
        {
            std::string_view error_name = magic_enum::enum_name(*val);
            throw Exception(DB::ErrorCodes::EXTERNAL_LIBRARY_ERROR, "resolveBlocking(): Ares query failed with error: {}", error_name);
        }
        else if (const auto * val = std::get_if<VariantOutputType>(&bridge_ptr_shared->output))
        {
            return std::move(*val);
        }
        else
        {
            throw Exception(DB::ErrorCodes::LOGICAL_ERROR, "resolveBlocking(): Invalid variant state");
        }
    }

    throw Exception(DB::ErrorCodes::TIMEOUT_EXCEEDED, "resolveBlocking(): Failed due to user-defined timeout");
}

}

namespace DB {

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
        throw Exception(ErrorCodes::EXTERNAL_LIBRARY_ERROR, "Failed to initialize the c-ares library");

    if (ares_init(&channel) != ARES_SUCCESS)
    {
        ares_library_cleanup();
        throw Exception(ErrorCodes::EXTERNAL_LIBRARY_ERROR, "Failed to initialize the c-ares channel");
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
            /// don't forget mutex here
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
