#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace DB
{

class SRVResolver
{
struct EndpointWithPriority {
    std::string endpoint;
    uint16_t priority;
};

public:
    SRVResolver(const std::string&);
    std::optional<std::string> getNextFreshEndpoint();

private:
    void scheduleResolution();
    void handleResponse(int, unsigned char *, int);

    static constexpr auto timeout_after{std::chrono::seconds{5}};
    size_t current_idx {0};
    std::string srv_endpoint;
    std::vector<EndpointWithPriority> endpoints;
    std::chrono::system_clock::time_point expired_at;
    mutable std::mutex mutex;
};

}
