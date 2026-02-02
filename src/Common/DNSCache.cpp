#include <mutex>
#include <Common/DNSCache.h>

#include <Common/CurrentMetrics.h>
#include <Common/Exception.h>
#include <Common/setThreadName.h>

/// USERTODO: Finish DNSCache.cpp

namespace CurrentMetrics
{

extern const Metric DNSHostsCacheBytes;
extern const Metric DNSHostsCacheSize;
extern const Metric DNSAddressesCacheBytes;
extern const Metric DNSAddressesCacheSize;

}

namespace DB
{

namespace ErrorCodes
{

extern const int BAD_ARGUMENTS;
extern const int DNS_ERROR;

}

using Hostname = DNSCache::Hostname;
using Hostnames = DNSCache::Hostnames;
using IPv4 = DNSCache::IPv4;
using IPv4s = DNSCache::IPv4s;
using IPv6 = DNSCache::IPv6;
using IPv6s = DNSCache::IPv6s;
using SRVName = DNSCache::SRVName;

/// Public DNSCache methods
DNSCache::DNSCache(const uint64_t update_period_in_s_, const size_t cache_max_size_, const size_t cache_max_entries_)
    : update_period_in_s{update_period_in_s_}
    , cache_max_size{cache_max_size_}
    , cache_max_entries{cache_max_entries_}
{
}

DNSCache::~DNSCache()
{
    disableBackgroundUpdates();
}

void DNSCache::enableBackgroundUpdates()
{
    std::lock_guard init_lock(updater_thread_mutex);
    if (updater_thread.joinable())
        return;

    updater_shutdown_flag = false;
    const auto update_cache_lambda = [this]
    {
        setThreadName(DB::ThreadName::DNS_CACHE_UPDATER);
        const auto should_wakeup_lambda = [this] { return updater_shutdown_flag.load(); };
        while (!updater_shutdown_flag)
        {
            update();

            std::unique_lock wakeup_lock(wakeup_mutex);
            wakeup_cv.wait_for(wakeup_lock, std::chrono::seconds(update_period_in_s), should_wakeup_lambda);
        }
    };
    updater_thread = ThreadFromGlobalPool{update_cache_lambda};
}

void DNSCache::disableBackgroundUpdates()
{
    updater_shutdown_flag = true;
    wakeup_cv.notify_all();
    std::lock_guard deinit_lock(updater_thread_mutex);
    if (updater_thread.joinable())
    {
        updater_thread.join();
        updater_thread = {};
    }
}

void DNSCache::clearCache()
{
    std::unique_lock write_lock(data_shared_mutex);
    ipv4s_entry_by_hostname.clear();
    ipv6s_entry_by_hostname.clear();
    hostnames_entry_by_ipv4.clear();
    hostnames_entry_by_ipv6.clear();
    hostnames_entry_by_srv_name.clear();
}

std::vector<std::pair<Hostname, IPv4s>> DNSCache::copyHostnameToIPv4sEntries() const
{
    std::vector<std::pair<Hostname, IPv4s>> output;
    output.reserve(ipv4s_entry_by_hostname.size());
    for (const auto & [hostname, ips] : ipv4s_entry_by_hostname)
        output.emplace_back(hostname, ips);
}
}

std::vector<std::pair<Hostname, IPv6s>> DNSCache::copyHostnameToIPv6sEntries() const
{
}

std::vector<std::pair<IPv4, Hostnames>> DNSCache::copyIPv4ToHostnamesEntries() const
{
}

std::vector<std::pair<IPv6, Hostnames>> DNSCache::copyIPv6ToHostnamesEntries() const
{
}

std::vector<std::pair<SRVName, Hostnames>> DNSCache::copySRVNameToHostnamesEntries() const
{
}

/// Private DNSCache methods

void DNSCache::update()
{
    std::unique_lock write_lock(data_shared_mutex);
}
}
