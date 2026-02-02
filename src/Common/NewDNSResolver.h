/// USERTODO Finish NewDNSResolver.h

#pragma once

#include <Poco/Net/IPAddress.h>

#include <optional>
#include <string>
#include <vector>

namespace DB
{

class DNSResolver
{
    using Hostname = std::string;
    using Hostnames = std::vector<Hostname>;
    using IPAddress = Poco::Net::IPAddress;
    using IPAddresses = std::vector<IPAddress>;

public:
    struct Settings
    {
        bool dns_allow_resolve_names_to_ipv4;
        bool dns_allow_resolve_names_to_ipv6;
    };

    struct SparseSettings
    {
        std::optional<bool> dns_allow_resolve_names_to_ipv4;
        std::optional<bool> dns_allow_resolve_names_to_ipv6;
    };

    static DNSResolver & instance();

    DNSResolver(const DNSResolver &) = delete;
    DNSResolver & operator=(const DNSResolver &) = delete;
    DNSResolver(DNSResolver &&) = delete;
    DNSResolver & operator=(DNSResolver &&) = delete;

    Hostname getLocalHostname();
    IPAddress resolveToPrioritizedIP(const Hostname & hostname);
    IPAddresses resolveToPrioritizedIPs(const Hostname & hostname);
    Hostnames resolveToVerifiedHostnames(const IPAddress & ip_address);
    bool isHostnameIP(const Hostname & hostname, const IPAddress & ip_address);
    bool isLocalhostIP(const IPAddress & ip_address);
    void reportFailure(const Hostname & hostname);

    void updateSettings(SparseSettings && sparse_settings);
    void initializeCache(size_t cache_max_size, size_t cache_max_entries);
    void deinitializeCache();

private:
    DNSResolver();
    ~DNSResolver();

    Settings settings;

    /// USERTODO: have a public method to get this hostname? Need to see if that is useful to the rest of the app even
    /// USERTODO: A, AAAA, SRV, PTR records. See what functions are needed for them.
    /// USERTODO: Check DNSResolver, check each method and see if it needs to be replicated into a method in this new resolver.
    ///             resolveHost() = resolveToPrioritizedIP()
    ///             etc ...
};

}
