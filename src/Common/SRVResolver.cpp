#include <Common/SRVResolver.h>


#include <algorithm>
#include <chrono>
#include <future>
#include <semaphore>

#include <ares.h>
#include <ares_nameser.h>

#include <base/defines.h>
#include <Common/AsyncAresExecutor.h>
#include <Common/Exception.h>

namespace DB
{

namespace ErrorCodes
{
extern const int FAILED_TO_RESOLVE;
extern const int EMPTY_RESOLUTION;
}

/**
 * @brief Constructs the SRVResolver and performs an initial synchronous DNS SRV resolution
 */
SRVResolver::SRVResolver(const std::string& srv_endpoint_)
    : srv_endpoint{srv_endpoint_}
{
    struct Bridge {
        std::promise<void> promise;
        SRVResolver * resolver;
    };

    /// We need to use unique_ptr to allocate on the heap, otherwise we get segfault
    auto bridge_ptr{std::make_unique<Bridge>(Bridge{std::promise<void>{}, this})};
    auto future{bridge_ptr->promise.get_future()};

    AsyncAresExecutor::instance().query(
        srv_endpoint.c_str(), ns_c_in, ns_t_srv,
        [](void * arg, int status, int /*timeouts*/, unsigned char * abuf, int alen)
        {
            std::unique_ptr<Bridge> lambda_bridge_ptr{static_cast<Bridge *>(arg)};
            lambda_bridge_ptr->resolver->handleResponse(status, abuf, alen);
            lambda_bridge_ptr->promise.set_value();
        },
        bridge_ptr.release()
    );

    /// Wait for the future or timeout
    if (future.wait_for(timeout_after) != std::future_status::ready) [[unlikely]]
    {
        throw Exception(ErrorCodes::FAILED_TO_RESOLVE, "SRVResolver::SRVResolver() resolution timed out for {}", srv_endpoint);
    }

    {
        std::lock_guard lock{mutex};
        if (endpoints.empty()) [[unlikely]]
            throw Exception(ErrorCodes::EMPTY_RESOLUTION, "SRV resolution returned no results for {}", srv_endpoint);
    }
}

std::optional<std::string> SRVResolver::getNextFreshEndpoint()
{
    {
        std::lock_guard lock{mutex};
        const bool is_expired = std::chrono::system_clock::now() >= expired_at;
        if (is_expired) [[unlikely]]
            scheduleResolution();

        const size_t N = endpoints.size();
        if (N == 0) [[unlikely]]
            return std::nullopt;

        const auto & endpoint{endpoints[current_idx].endpoint};
        current_idx = (current_idx + 1) % N;

        return std::make_optional<std::string>(endpoint);
    }
}

void SRVResolver::scheduleResolution()
{
    AsyncAresExecutor::instance().query(
        srv_endpoint.c_str(), ns_c_in, ns_t_srv,
        [](void * arg, int status, int, unsigned char * abuf, int alen)
        {
            static_cast<SRVResolver *>(arg)->handleResponse(status, abuf, alen);
        },
        this
    );
}

void SRVResolver::handleResponse(int status, unsigned char * abuf, int alen)
{
    if (status != ARES_SUCCESS) [[unlikely]]
        return;

    /// ares_parse_srv_reply allocates a linked list of ares_srv_reply structs
    struct ares_srv_reply * reply = nullptr;
    int parse_status = ares_parse_srv_reply(abuf, alen, &reply);
    if (parse_status != ARES_SUCCESS || !reply) [[unlikely]]
        return;
    /// Extract minimum TTL, clamped to 5s minimum and 3600s maximum
    uint32_t min_ttl = 3600; 
    ns_msg msg;
    if (ns_initparse(abuf, alen, &msg) == 0) [[likely]]
    {
        const auto count = ns_msg_count(msg, ns_s_an);
        for (auto i = 0; i < count; ++i)
        {
            ns_rr rr;
            if (ns_parserr(&msg, ns_s_an, i, &rr) == 0) [[likely]]
            {
                min_ttl = std::min(min_ttl, static_cast<uint32_t>(ns_rr_ttl(rr)));
            }
        }
    }
    min_ttl = std::clamp(min_ttl, 5u, 3600u);

    /// Extract endpoints
    std::vector<EndpointWithPriority> new_endpoints;
    for (auto * curr = reply; curr != nullptr; curr = curr->next)
    {
        if (const char * host = curr->host; host && *host) [[likely]]
        {
            new_endpoints.emplace_back(EndpointWithPriority{
                std::string(host) + ":" + std::to_string(curr->port),
                static_cast<uint16_t>(curr->priority)
            });
        }
    }

    ares_free_data(reply);

    if (new_endpoints.empty()) [[unlikely]]
        return;

    std::sort(
        new_endpoints.begin(), new_endpoints.end(),
        [](const EndpointWithPriority & a, const EndpointWithPriority & b)
        {
            return a.priority < b.priority;
        }
    );

    {
        std::lock_guard lock{mutex};
        endpoints = std::move(new_endpoints);
        current_idx = 0;
        expired_at = std::chrono::system_clock::now() + std::chrono::seconds(min_ttl);
    }
}

}
