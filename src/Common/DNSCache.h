#pragma once

#include <Common/ThreadPool.h>

#include <boost/functional/hash.hpp>
#include <boost/unordered/unordered_flat_map.hpp>
#include <netinet/in.h>
#include <Poco/Net/IPAddress.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <memory_resource>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace DB
{

namespace detail
{

struct TransparentStringHash
{
    using is_transparent = void;
    size_t operator()(std::string_view sv) const { return boost::hash<std::string_view>{}(sv); }
};

struct ItemsMetadata
{
    std::chrono::steady_clock::time_point last_used_at;
    std::chrono::steady_clock::time_point expires_at;
};

template <typename T>
struct Item
{
    using allocator_type = std::pmr::polymorphic_allocator<T>;

    uint8_t num_failures;
    T item;

    Item(const Item &) = default;
    Item(Item &&) noexcept = default;

    explicit Item(T val)
        : num_failures(0)
        , item(std::move(val))
    {
    }

    explicit Item(T val, const allocator_type & alloc)
        : num_failures(0)
        , item(std::make_obj_using_allocator<T>(alloc, std::move(val)))
    {
    }

    Item(const Item & other, const allocator_type & alloc)
        : num_failures(other.num_failures)
        , item(std::make_obj_using_allocator<T>(alloc, other.item))
    {
    }

    /// Can throw if: new allocator + not enough memory
    Item(Item && other, const allocator_type & alloc) // NOLINT(hicpp-noexcept-move, performance-noexcept-move-constructor)
        : num_failures(other.num_failures)
        , item(std::make_obj_using_allocator<T>(alloc, std::move(other.item)))
    {
    }
};

template <typename T>
struct Items
{
    using allocator_type = std::pmr::polymorphic_allocator<T>;

    ItemsMetadata metadata;
    std::pmr::vector<Item<T>> items;

    Items() = default;
    Items(const Items &) = default;
    Items(Items &&) = default;

    explicit Items(const allocator_type & alloc)
        : items(alloc)
    {
    }

    Items(const Items & other, const allocator_type & alloc)
        : metadata(other.metadata)
        , items(other.items, alloc)
    {
    }

    /// Can throw if: new allocator + not enough memory
    Items(Items && other, const allocator_type & alloc) // NOLINT(hicpp-noexcept-move, performance-noexcept-move-constructor)
        : metadata(std::move(other.metadata))
        , items(std::move(other.items), alloc)
    {
    }
};

}

class DNSCache
{
public:
    /// Types
    template <typename K, typename V, typename H>
    using CacheMap = boost::unordered::unordered_flat_map<K, V, H, std::equal_to<>, std::pmr::polymorphic_allocator<std::pair<const K, V>>>;

    using Hostname = std::string;
    using IPv4 = in_addr;
    using IPv6 = in6_addr;
    using SRVName = std::string;

    using Hostnames = std::vector<Hostname>;
    using IPv4s = std::vector<IPv4>;
    using IPv6s = std::vector<IPv6>;

    using HostnamePMR = std::pmr::string;
    using SRVNamePMR = std::pmr::string;

    using HostnamesEntry = detail::Items<HostnamePMR>;
    using IPv4sEntry = detail::Items<IPv4>;
    using IPv6sEntry = detail::Items<IPv6>;


    /// Methods
    DNSCache(uint64_t update_period_in_s_, size_t cache_max_size_, size_t cache_max_entries_);
    ~DNSCache();

    void enableBackgroundUpdates();
    void disableBackgroundUpdates();
    void clearCache();

    std::vector<std::pair<Hostname, IPv4s>> copyHostnameToIPv4sEntries() const;
    std::vector<std::pair<Hostname, IPv6s>> copyHostnameToIPv6sEntries() const;
    std::vector<std::pair<IPv4, Hostnames>> copyIPv4ToHostnamesEntries() const;
    std::vector<std::pair<IPv6, Hostnames>> copyIPv6ToHostnamesEntries() const;
    std::vector<std::pair<SRVName, Hostnames>> copySRVNameToHostnamesEntries() const;

    void addHostnameToIPv4sEntry(Hostname & hostname, IPv4s & ipv4_addresses);
    void addHostnameToIPv6sEntry(Hostname & hostname, IPv6s & ipv6_addresses);
    void addIPv4ToHostnamesEntry(IPv4 & ipv4_address, Hostnames & hostnames);
    void addIPv6ToHostnamesEntry(IPv6 & ipv6_address, Hostnames & hostnames);
    void addSRVToHostnamesEntry(SRVName & srv_name, Hostnames & hostnames);

    std::optional<IPv4s> getIPv4sOfHostname(const Hostname & hostname);
    std::optional<IPv6s> getIPv6sOfHostname(const Hostname & hostname);
    std::optional<Hostnames> getHostnamesOfIPv4(const IPv4 & ipv4_address);
    std::optional<Hostnames> getHostnamesOfIPv6(const IPv6 & ipv6_address);
    std::optional<Hostnames> getHostnamesOfSRVName(const SRVName & srv_name);

    void reportFailureIPv4OfHostname(const IPv4 & ipv4_address, const Hostname & hostname);
    void reportFailureIPv6OfHostname(const IPv6 & ipv6_address, const Hostname & hostname);
    void reportFailureHostnameOfIPv4(const Hostname & hostname, const IPv4 & ipv4_address);
    void reportFailureHostnameOfIPv6(const Hostname & hostname, const IPv6 & ipv6_address);
    void reportFailureHostnameOfSRVName(const Hostname & hostname, const SRVName & srv_name);

private:
    void update();

    /// Members
    std::atomic<bool> updater_shutdown_flag{false};
    std::condition_variable wakeup_cv;
    std::mutex wakeup_mutex;
    std::mutex updater_thread_mutex;
    ThreadFromGlobalPool updater_thread;

    const uint64_t update_period_in_s;
    const size_t cache_max_size;
    const size_t cache_max_entries;

    std::shared_mutex data_shared_mutex;
    std::pmr::synchronized_pool_resource pool;
    CacheMap<HostnamePMR, IPv4sEntry, detail::TransparentStringHash> ipv4s_entry_by_hostname{&pool};
    CacheMap<HostnamePMR, IPv6sEntry, detail::TransparentStringHash> ipv6s_entry_by_hostname{&pool};
    CacheMap<IPv4, HostnamesEntry, boost::hash<IPv4>> hostnames_entry_by_ipv4{&pool};
    CacheMap<IPv6, HostnamesEntry, boost::hash<IPv6>> hostnames_entry_by_ipv6{&pool};
    CacheMap<SRVNamePMR, HostnamesEntry, detail::TransparentStringHash> hostnames_entry_by_srv_name{&pool};

    /// USERTODO: POCO IP ADDRESS doesn't work with PMR, create internal IP address instead, like in6_addr and in_addr maybe?
    /// USERTODO: Properly use metrics to show actual cache size (all caches)
    ///     That means manually increasing and decreasing the size on each new entry and each deleted entry
    /// USERTODO: track max_failures, and evict cache entries that failed more than x times (failed for connection)
    /// USERTODO: Remove cache entries that fail to be updated by DNS more than x times
    /// USERTODO: track last_used, and evict half of least used cache entries on hitting memory limits
    /// USERTODO: Metrics: DNSHostsCacheBytes, DNSHostsCacheSize, DNSAddressesCacheBytes, DNSAddressesCacheSize
    /// USERTODO: Use CurrentMetrics::add and CurrentMetrics::sub for addition and subtraction
};

}
