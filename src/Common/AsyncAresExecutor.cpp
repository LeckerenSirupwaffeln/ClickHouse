#include <Common/AsyncAresExecutor.h>

#include <base/defines.h>
#include <Common/Exception.h>
#include <Common/EPoll.h>

#include <ares_nameser.h>

#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <algorithm>
#include <future>
#include <string>
#include <vector>

namespace {

constexpr uint32_t MIN_TTL = 5u;
constexpr uint32_t MAX_TTL = 3600u;

struct SocketAddressWithPriority
{
    /// socket_address is just a hostname with a port number, i.e: example.com:1234
    std::string socket_address;
    uint16_t priority;
};

struct ResolvedSRVOutput
{
    std::vector<SocketAddressWithPriority> socket_addresses_with_priority;
    uint32_t min_ttl;
};

template <typename T>
struct OutputWithBinarySemaphore
{
    std::binary_semaphore sem{0};
    T output;
};

std::optional<ResolvedSRVOutput> HandleResponseSRV(int status, unsigned char * abuf, int alen)
{
    if (status != ARES_SUCCESS) [[unlikely]]
        return std::nullopt;

    struct ares_srv_reply * reply = nullptr;
    int parse_status = ares_parse_srv_reply(abuf, alen, &reply);
    if (parse_status != ARES_SUCCESS || !reply) [[unlikely]]
        return std::nullopt;

    ResolvedSRVOutput output;

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
        return std::nullopt;

    std::sort(
        output_vec.begin(), output_vec.end(),
        [](const SocketAddressWithPriority & a, const SocketAddressWithPriority & b)
        {
            return a.priority < b.priority;
        }
    );

    return output;
}

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


void resolveHostnameBlocking(const std::string& hostname, ares_addrinfo_callback cb, void * user_data)
{
    struct ares_addrinfo_hints hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; /// Requests both A and AAAA records (IPv4 and IPv6)
    ares_getaddrinfo(channel, hostname.c_str(), nullptr, &hints, cb, user_data);
}

void resolveIPBlocking(const std::string& ip_str, ares_callback cb, void * user_data)
{
    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (ares_inet_pton(AF_INET, ip_str.c_str(), &ipv4) == 1)
        ares_gethostbyaddr(channel, &ipv4, sizeof(ipv4), AF_INET, cb, user_data);
    else if (ares_inet_pton(AF_INET6, ip_str.c_str(), &ipv6) == 1)
        ares_gethostbyaddr(channel, &ipv6, sizeof(ipv6), AF_INET6, cb, user_data);
    else
        throw Exception(ErrorCodes::INVALID_IP_ADDRESS_FORMAT, "Invalid I.P address format: {}", ip_str);
}

std::optional<ResolvedSRVOutput> resolveSRVBlocking(const std::string& service_record, const uint32_t timeout_ms)
{
    using BridgeType = OutputWithBinarySemaphore<std::optional<ResolvedSRVOutput>>;
    auto bridge_ptr_shared = std::make_shared<BridgeType>();

    /// Keeps the object inside bridge_ptr_shared alive even if callback happens after this function goes out of scope
    /// Will not leak as callbacks are guaranteed with c-ares as long as we ares_destroy() the ares channel on shutdown
    auto bridge_ptr_callback = std::make_unique<std::shared_ptr<BridgeType>>(bridge_ptr_shared);
    auto srv_callback = [](void * arg, int status, int /*timeouts*/, unsigned char * abuf, int alen)
    {
        auto bridge_ptr = std::unique_ptr<std::shared_ptr<BridgeType>>(
            static_cast<std::shared_ptr<BridgeType> *>(arg)
        );
        auto& bridge = **bridge_ptr;
        bridge.output = HandleResponseSRV(status, abuf, alen);
        bridge.sem.release(); /// Signal our callback as completed
    };

    ares_query(channel, service_record.c_str(), ARES_CLASS_IN, ARES_REC_TYPE_SRV, srv_callback, bridge_ptr_callback.release());

    if (bridge_ptr_shared->sem.try_acquire_for(std::chrono::milliseconds(timeout_ms)))
    {
        return bridge_ptr_shared->output;
    }

    return std::nullopt;
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
