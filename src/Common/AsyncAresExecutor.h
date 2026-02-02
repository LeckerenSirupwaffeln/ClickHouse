#pragma once

#include <ares.h>
#include <netinet/in.h>

#include <atomic>
#include <cstdint>
#include <expected>
#include <functional>
#include <string>
#include <vector>

namespace DB
{

/// A thread-safe singleton wrapper for the c-ares asynchronous resolver library.
/// It ensures the library and its internal channel are initialized once and cleaned up on exit.
/// Request processing is handled automatically in the background by a thread spawned by c-ares.
class AsyncAresExecutor
{
public:
    enum class ErrorCode : std::uint8_t
    {
        /// Ares query errors
        AresQueryNetworkParamsError, /// (Windows) Failed to retrieve network parameters.
        AresQueryInvalidAddressFamily, /// The requested address family (IPv4/IPv6) is not supported.
        AresQueryInvalidFlags, /// Invalid flags passed to the library function.
        AresQueryInvalidHints, /// Invalid hints provided for address lookups.
        AresQueryInvalidName, /// The provided domain name contains illegal characters.
        AresQueryInvalidQuery, /// The DNS query structure is malformed.
        AresQueryInvalidResponse, /// Server sent a malformed or unparseable response.
        AresQueryInvalidString, /// A malformed string was provided to the library.
        AresQueryCancelled, /// The query was explicitly cancelled by the user.
        AresQueryConnectionRefused, /// Could not connect to the DNS server.
        AresQueryChannelDestroyed, /// The channel was destroyed while the query was pending.
        AresQueryConfigurationFileError, /// Error reading configuration files (e. g. , resolv. conf).
        AresQueryFormError, /// Server claimed the query was formatted incorrectly.
        AresQueryLoadLibraryError, /// (Windows) Failed to load iphlpapi. dll.
        AresQueryNoData, /// Domain exists, but has no records of the requested type.
        AresQueryOutOfMemory, /// Memory allocation failed.
        AresQueryNoName, /// Hostname could not be resolved (internal/system lookup).
        AresQueryNotFound, /// Domain name not found (NXDOMAIN).
        AresQueryNotImplemented, /// Server does not support the requested operation.
        AresQueryNotInitialized, /// The library was not properly initialized.
        AresQueryNotSpecial, /// Name is not a "special" name (used in specific lookup types).
        AresQueryEndOfFile, /// Unexpected end of file/stream during TCP connection.
        AresQueryRefused, /// The DNS server refused the query (e. g. , ACL/Policy).
        AresQueryServerFailure, /// DNS server reported a general internal failure.
        AresQueryTimeout, /// No response received within the timeout period.
        AresQueryUnknown, /// Unknown ares query error
    };

    struct ARecord
    {
        uint32_t ttl;
        in_addr ipv4_address;
    };

    struct AAAARecord
    {
        uint32_t ttl;
        in6_addr ipv6_address;
    };

    struct PTRRecord
    {
        uint32_t ttl;
        std::string domain_name;
    };

    struct SRVRecord
    {
        uint32_t ttl;
        uint16_t priority;
        uint16_t weight;
        uint16_t port;
        std::string target;
    };

    static constexpr uint32_t MIN_TTL = 60u;
    static constexpr uint32_t MAX_TTL = 86400u;

    using ARecordsCallback = void (*)(std::expected<std::vector<ARecord>, ErrorCode> &&);
    using AAAARecordsCallback = void (*)(std::expected<std::vector<AAAARecord>, ErrorCode> &&);
    using PTRRecordsCallback = void (*)(std::expected<std::vector<PTRRecord>, ErrorCode> &&);
    using SRVRecordsCallback = void (*)(std::expected<std::vector<SRVRecord>, ErrorCode> &&);

    AsyncAresExecutor(const AsyncAresExecutor &) = delete;
    AsyncAresExecutor & operator=(const AsyncAresExecutor &) = delete;
    AsyncAresExecutor(AsyncAresExecutor &&) = delete;
    AsyncAresExecutor & operator=(AsyncAresExecutor &&) = delete;

    static AsyncAresExecutor & instance();
    void shutdown();

    void queryARecords(const std::string &, ARecordsCallback);
    void queryAAAARecords(const std::string &, AAAARecordsCallback);
    void queryPTRRecords(const std::string &, PTRRecordsCallback);
    void querySRVRecords(const std::string &, SRVRecordsCallback);

    std::vector<ARecord> queryARecordsBlocking(const std::string &, const uint32_t);
    std::vector<AAAARecord> queryAAAARecordsBlocking(const std::string &, const uint32_t);
    std::vector<PTRRecord> queryPTRRecordsBlocking(const std::string &, const uint32_t);
    std::vector<SRVRecord> querySRVRecordsBlocking(const std::string &, const uint32_t);

private:
    AsyncAresExecutor();
    ~AsyncAresExecutor();

    ares_channel channel{nullptr};
    std::atomic<bool> is_shutdown_called{false};
};

}
