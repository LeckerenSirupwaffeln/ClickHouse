#include <Common/AsyncAresExecutor.h>

#include <base/defines.h>
#include <Common/Exception.h>

#include <ares.h>
#include <netinet/in.h>
#include <magic_enum.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <concepts>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <semaphore>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace DB
{

namespace ErrorCodes
{
extern const int INVALID_IP_ADDRESS_FORMAT;
extern const int EXTERNAL_LIBRARY_ERROR;
extern const int TIMEOUT_EXCEEDED;
}

}

namespace
{

using ::AsyncAresExecutor::ErrorCode;
using ::AsyncAresExecutor::MAX_TTL;
using ::AsyncAresExecutor::MIN_TTL;

template <typename T>
struct AsyncResult
{
    std::binary_semaphore sem{0};
    std::expected<T, ErrorCode> result;
};

enum class QueryType
{
    A_RECORD,
    AAAA_RECORD,
    PTR_RECORD,
    SRV_RECORD,
};

std::vector<ARecord> handleResponseARecord(const ares_dns_record_t *) noexcept;
std::vector<AAAARecord> handleResponseAAAARecord(const ares_dns_record_t *) noexcept;
std::vector<PTRRecord> handleResponsePTRRecord(const ares_dns_record_t *) noexcept;
std::vector<SRVRecord> handleResponseSRVRecord(const ares_dns_record_t *) noexcept;
template <QueryType Q>
consteval auto get_handler()
{
    if constexpr (Q == QueryType::A_RECORD)
        return &handleResponseARecord;
    else if constexpr (Q == QueryType::AAAA_RECORD)
        return &handleResponseAAAARecord;
    else if constexpr (Q == QueryType::PTR_RECORD)
        return &handleResponsePTRRecord;
    else if constexpr (Q == QueryType::SRV_RECORD)
        return &handleResponseSRVRecord;
    else
        static_assert(Q != Q, "Unsupported template QueryType provided to get_handler()");
}

/// Forward declarations of our customized ares query functions
int aresQueryARecord(ares_channel, const char *, ares_callback, void *);
int aresQueryAAAARecord(ares_channel, const char *, ares_callback, void *);
int aresQueryPTRRecord(ares_channel, const char *, ares_callback, void *);
int aresQuerySRVRecord(ares_channel, const char *, ares_callback, void *);
template <QueryType Q>
consteval auto get_query_function()
{
    if constexpr (Q == QueryType::A_RECORD)
        return &aresQueryARecord;
    else if constexpr (Q == QueryType::AAAA_RECORD)
        return &aresQueryAAAARecord;
    else if constexpr (Q == QueryType::PTR_RECORD)
        return &aresQueryPTRRecord;
    else if constexpr (Q == QueryType::SRV_RECORD)
        return &aresQuerySRVRecord;
    else
        static_assert(Q != Q, "Unsupported template QueryType provided to get_query_function()");
}

constexpr ErrorCode ares_status_to_error_code(int status) noexcept
{
    switch (status)
    {
        case ARES_EADDRGETNETWORKPARAMS:
            return ErrorCode::AresQueryNetworkParamsError;
        case ARES_EBADFAMILY:
            return ErrorCode::AresQueryInvalidAddressFamily;
        case ARES_EBADFLAGS:
            return ErrorCode::AresQueryInvalidFlags;
        case ARES_EBADHINTS:
            return ErrorCode::AresQueryInvalidHints;
        case ARES_EBADNAME:
            return ErrorCode::AresQueryInvalidName;
        case ARES_EBADQUERY:
            return ErrorCode::AresQueryInvalidQuery;
        case ARES_EBADRESP:
            return ErrorCode::AresQueryInvalidResponse;
        case ARES_EBADSTR:
            return ErrorCode::AresQueryInvalidString;
        case ARES_ECANCELLED:
            return ErrorCode::AresQueryCancelled;
        case ARES_ECONNREFUSED:
            return ErrorCode::AresQueryConnectionRefused;
        case ARES_EDESTRUCTION:
            return ErrorCode::AresQueryChannelDestroyed;
        case ARES_EFILE:
            return ErrorCode::AresQueryConfigurationFileError;
        case ARES_EFORMERR:
            return ErrorCode::AresQueryFormError;
        case ARES_ELOADIPHLPAPI:
            return ErrorCode::AresQueryLoadLibraryError;
        case ARES_ENODATA:
            return ErrorCode::AresQueryNoData;
        case ARES_ENOMEM:
            return ErrorCode::AresQueryOutOfMemory;
        case ARES_ENONAME:
            return ErrorCode::AresQueryNoName;
        case ARES_ENOTFOUND:
            return ErrorCode::AresQueryNotFound;
        case ARES_ENOTIMP:
            return ErrorCode::AresQueryNotImplemented;
        case ARES_ENOTINITIALIZED:
            return ErrorCode::AresQueryNotInitialized;
        case ARES_ENOTSPECIAL:
            return ErrorCode::AresQueryNotSpecial;
        case ARES_EOF:
            return ErrorCode::AresQueryEndOfFile;
        case ARES_EREFUSED:
            return ErrorCode::AresQueryRefused;
        case ARES_ESERVFAIL:
            return ErrorCode::AresQueryServerFailure;
        case ARES_ETIMEOUT:
            return ErrorCode::AresQueryTimeout;
        default:
            return ErrorCode::AresQueryUnknown;
    }
}

std::vector<ARecord> handleResponseARecord(const ares_dns_record_t * dnsrec) noexcept
{
    std::vector<ARecord> result;
    const size_t count = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
    for (size_t i = 0; i < count; ++i)
    {
        ares_dns_rr_t * rr = ares_dns_record_get_rr(dnsrec, ARES_SECTION_ANSWER, i);
        if (ares_dns_rr_get_type(rr) != ARES_REC_TYPE_A)
            continue;

        uint32_t ttl = ares_dns_rr_get_ttl(rr);
        if (ttl > 0)
            ttl = std::clamp(ttl, MIN_TTL, MAX_TTL); /// Clamp only positive cacheable TTL

        const auto * addr = static_cast<const in_addr *>(ares_dns_rr_get_addr(rr, ARES_RR_A_ADDR));
        if (!addr)
            continue;
        result.emplace_back(ARecord{
            .ttl = ttl,
            .ipv4_address = *addr,
        });
    }

    return result;
}

std::vector<AAAARecord> handleResponseAAAARecord(const ares_dns_record_t * dnsrec) noexcept
{
    std::vector<AAAARecord> result;
    const size_t count = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
    for (size_t i = 0; i < count; ++i)
    {
        ares_dns_rr_t * rr = ares_dns_record_get_rr(dnsrec, ARES_SECTION_ANSWER, i);
        if (ares_dns_rr_get_type(rr) != ARES_REC_TYPE_AAAA)
            continue;

        uint32_t ttl = ares_dns_rr_get_ttl(rr);
        if (ttl > 0)
            ttl = std::clamp(ttl, MIN_TTL, MAX_TTL); /// Clamp only positive cacheable TTL

        const auto * addr = static_cast<const in6_addr *>(ares_dns_rr_get_addr(rr, ARES_RR_AAAA_ADDR));
        if (!addr)
            continue;
        result.emplace_back(AAAARecord{
            .ttl = ttl,
            .ipv6_address = *addr,
        });
    }

    return result;
}

std::vector<PTRRecord> handleResponsePTRRecord(const ares_dns_record_t * dnsrec) noexcept
{
    static_assert(
        std::is_same_v<decltype(PTRRecord::domain_name), std::string>,
        "PTRRecord::domain_name must be std::string to safely copy null-terminated char * dname");

    std::vector<PTRRecord> result;
    const size_t count = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
    for (size_t i = 0; i < count; ++i)
    {
        ares_dns_rr_t * rr = ares_dns_record_get_rr(dnsrec, ARES_SECTION_ANSWER, i);
        if (ares_dns_rr_get_type(rr) != ARES_REC_TYPE_PTR)
            continue;

        uint32_t ttl = ares_dns_rr_get_ttl(rr);
        if (ttl > 0)
            ttl = std::clamp(ttl, MIN_TTL, MAX_TTL); /// Clamp only positive cacheable TTL

        const char * dname = ares_dns_rr_get_str(rr, ARES_RR_PTR_DNAME);
        if (!dname)
            continue;
        result.emplace_back(PTRRecord{
            .ttl = ttl,
            .domain_name = dname,
        });
    }

    return result;
}

std::vector<SRVRecord> handleResponseSRVRecord(const ares_dns_record_t * dnsrec) noexcept
{
    static_assert(
        std::is_same_v<decltype(SRVRecord::target), std::string>,
        "SRVRecord::target must be std::string to safely copy null-terminated char * target");

    std::vector<SRVRecord> result;
    const size_t count = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
    for (size_t i = 0; i < count; ++i)
    {
        ares_dns_rr_t * rr = ares_dns_record_get_rr(dnsrec, ARES_SECTION_ANSWER, i);
        if (ares_dns_rr_get_type(rr) != ARES_REC_TYPE_SRV)
            continue;

        uint32_t ttl = ares_dns_rr_get_ttl(rr);
        if (ttl > 0)
            ttl = std::clamp(ttl, MIN_TTL, MAX_TTL); /// Clamp only positive cacheable TTL

        const uint16_t priority = ares_dns_rr_get_int16(rr, ARES_RR_SRV_PRIORITY);
        const uint16_t weight = ares_dns_rr_get_int16(rr, ARES_RR_SRV_WEIGHT);
        const uint16_t port = ares_dns_rr_get_int16(rr, ARES_RR_SRV_PORT);
        const char * target = ares_dns_rr_get_str(rr, ARES_RR_SRV_TARGET);
        if (!target)
            continue;
        result.emplace_back(SRVRecord{
            .ttl = ttl,
            .priority = priority,
            .weight = weight,
            .port = port,
            .target = target,
        });
    }

    return result;
}

ALWAYS_INLINE int aresQueryARecord(ares_channel channel, const char * name, ares_callback cb, void * arg)
{
    return ares_dns_query(channel, name, ARES_CLASS_IN, ARES_REC_TYPE_A, cb, arg, nullptr);
}

ALWAYS_INLINE int aresQueryAAAARecord(ares_channel channel, const char * name, ares_callback cb, void * arg)
{
    return ares_dns_query(channel, name, ARES_CLASS_IN, ARES_REC_TYPE_AAAA, cb, arg, nullptr);
}

ALWAYS_INLINE int aresQueryPTRRecord(ares_channel channel, const char * name, ares_callback cb, void * arg)
{
    unsigned char buf[16];
    int family;

    if (ares_inet_pton(AF_INET, name, buf) == 1)
        family = AF_INET;
    else if (ares_inet_pton(AF_INET6, name, buf) == 1)
        family = AF_INET6;
    else
        throw DB::Exception(DB::ErrorCodes::INVALID_IP_ADDRESS_FORMAT, "aresQueryPTRRecord(): Invalid I.P address format: {}", name);

    char * dns_ptr = nullptr;
    int status = ares_dns_ptr_from_addr(family, buf, &dns_ptr);
    if (status != ARES_SUCCESS)
    {
        if (dns_ptr)
            ares_free_string(dns_ptr);
        throw DB::Exception(
            DB::ErrorCodes::EXTERNAL_LIBRARY_ERROR, "aresQueryPTRRecord(): Failed to create DNS pointer from address: {}", name);
    }

    int result = ares_dns_query(channel, dns_ptr, ARES_CLASS_IN, ARES_REC_TYPE_PTR, cb, arg, nullptr);
    ares_free_string(dns_ptr);
    return result;
}

ALWAYS_INLINE int aresQuerySRVRecord(ares_channel channel, const char * name, ares_callback cb, void * arg)
{
    return ares_dns_query(channel, name, ARES_CLASS_IN, ARES_REC_TYPE_SRV, cb, arg, nullptr);
}

template <QueryType Q, typename C>
ALWAYS_INLINE void query(ares_channel channel, const std::string & input, C user_callback)
{
    using ResultType = std::invoke_result_t<decltype(get_handler<Q>()), const ares_dns_record_t *>;
    using CallbackArgType = std::expected<ResultType, ErrorCode>;
    static_assert(std::invocable<C, CallbackArgType>, "Callback C must be invokable with an argument of type CallbackArgumentType");

    struct CallbackOnHeap
    {
        C user_callback;
    };
    auto ptr_user_callback = std::make_unique<CallbackOnHeap>(user_callback);

    auto query_callback = [](void * arg, int status, size_t /*timeouts*/, const ares_dns_record_t * dnsrec)
    {
        auto heap_cb = std::unique_ptr<CallbackOnHeap>(static_cast<CallbackOnHeap *>(arg));
        if (status != ARES_SUCCESS) [[unlikely]]
        {
            heap_cb->user_callback(CallbackArgType{std::unexpected(ares_status_to_error_code(status))});
            return;
        }

        constexpr auto handler = get_handler<Q>();
        auto res = handler(dnsrec);
        heap_cb->user_callback(CallbackArgType{std::move(res)});
    };

    constexpr auto query_func = get_query_function<Q>();
    int status = query_func(channel, input.c_str(), query_callback, ptr_user_callback.get());
    if (status != ARES_SUCCESS) [[unlikely]]
    {
        throw DB::Exception(
            DB::ErrorCodes::EXTERNAL_LIBRARY_ERROR, "query(): Failed to enqueue query with error: {}", ares_strerror(status));
    }

    ptr_user_callback.release();
}

template <QueryType Q>
ALWAYS_INLINE auto queryBlocking(ares_channel channel, const std::string & input, const uint32_t timeout_ms)
{
    using ResultType = std::invoke_result_t<decltype(get_handler<Q>()), const ares_dns_record_t *>;
    using BridgeType = AsyncResult<ResultType>;
    auto bridge_ptr_shared = std::make_shared<BridgeType>();

    /// Keeps the object inside bridge_ptr_shared alive even if callback happens after this function goes out of scope
    /// Will not leak memory as callbacks are guaranteed with c-ares as long as we ares_destroy() the ares channel on shutdown
    auto bridge_ptr_callback = std::make_unique<std::shared_ptr<BridgeType>>(bridge_ptr_shared);

    auto query_callback = [](void * arg, int status, size_t /*timeouts*/, const ares_dns_record_t * dnsrec)
    {
        auto bridge_ptr = std::unique_ptr<std::shared_ptr<BridgeType>>(static_cast<std::shared_ptr<BridgeType> *>(arg));
        auto & bridge = **bridge_ptr;

        if (status != ARES_SUCCESS) [[unlikely]]
        {
            bridge.result = std::unexpected(ares_status_to_error_code(status));
        }
        else
        {
            constexpr auto handler = get_handler<Q>();
            bridge.result = handler(dnsrec);
        }

        bridge.sem.release(); /// Signal our callback as completed
    };

    constexpr auto query_func = get_query_function<Q>();
    int status = query_func(channel, input.c_str(), query_callback, bridge_ptr_callback.get());
    if (status != ARES_SUCCESS) [[unlikely]]
    {
        throw DB::Exception(
            DB::ErrorCodes::EXTERNAL_LIBRARY_ERROR, "queryBlocking(): Failed to enqueue query with error: {}", ares_strerror(status));
    }

    bridge_ptr_callback.release();

    if (bridge_ptr_shared->sem.try_acquire_for(std::chrono::milliseconds(timeout_ms)))
    {
        auto & res = bridge_ptr_shared->result;
        if (res)
        {
            return std::move(*res);
        }

        std::string_view error_name = magic_enum::enum_name(res.error());
        throw DB::Exception(DB::ErrorCodes::EXTERNAL_LIBRARY_ERROR, "queryBlocking(): Ares query failed with error: {}", error_name);
    }

    throw DB::Exception(DB::ErrorCodes::TIMEOUT_EXCEEDED, "queryBlocking(): Failed due to user-defined timeout");
}

}

namespace DB
{

using ::AsyncAresExecutor::AAAARecordsCallback;
using ::AsyncAresExecutor::ARecordsCallback;
using ::AsyncAresExecutor::PTRRecordsCallback;
using ::AsyncAresExecutor::SRVRecordsCallback;

/// Public methods
AsyncAresExecutor & AsyncAresExecutor::instance()
{
    static AsyncAresExecutor instance;
    return instance;
}

void AsyncAresExecutor::shutdown()
{
    if (is_shutdown_called.exchange(true))
        return;

    if (channel)
    {
        ares_destroy(channel);
        channel = nullptr;
    }
}

void AsyncAresExecutor::queryARecords(const std::string & domain_name, ARecordsCallback user_callback)
{
    query<QueryType::A_RECORD>(this->channel, domain_name, user_callback);
}

void AsyncAresExecutor::queryAAAARecords(const std::string & domain_name, AAAARecordsCallback user_callback)
{
    query<QueryType::AAAA_RECORD>(this->channel, domain_name, user_callback);
}

void AsyncAresExecutor::queryPTRRecords(const std::string & ip_address, PTRRecordsCallback user_callback)
{
    query<QueryType::PTR_RECORD>(this->channel, ip_address, user_callback);
}

void AsyncAresExecutor::querySRVRecords(const std::string & service_id, SRVRecordsCallback user_callback)
{
    query<QueryType::SRV_RECORD>(this->channel, service_id, user_callback);
}


std::vector<ARecord> AsyncAresExecutor::queryARecordsBlocking(const string & domain_name, const uint32_t timeout_ms)
{
    return queryBlocking<QueryType::A_RECORD>(this->channel, domain_name, timeout_ms);
}

std::vector<AAAARecord> AsyncAresExecutor::queryAAAARecordsBlocking(const string & domain_name, const uint32_t timeout_ms)
{
    return queryBlocking<QueryType::AAAA_RECORD>(this->channel, domain_name, timeout_ms);
}

std::vector<PTRRecord> AsyncAresExecutor::queryPTRRecordsBlocking(const string & ip_address, const uint32_t timeout_ms)
{
    return queryBlocking<QueryType::PTR_RECORD>(this->channel, ip_address, timeout_ms);
}

std::vector<SRVRecord> AsyncAresExecutor::querySRVRecordsBlocking(const string & service_id, const uint32_t timeout_ms)
{
    return queryBlocking<QueryType::SRV_RECORD>(this->channel, service_id, timeout_ms);
}


/// Private methods
AsyncAresExecutor::AsyncAresExecutor()
{
    /// Only use this class to init the ares library
    /// Do not init ares library multiple times within a program
    if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS)
        throw Exception(ErrorCodes::EXTERNAL_LIBRARY_ERROR, "AsyncAresExecutor(): Failed to initialize the c-ares library");

    struct ares_options options
    {
    };

    /// Better performance with reusing sockets
    /// As long as we use few channels (<100), this is OK and will not hit FD limits
    options.flags = ARES_FLAG_STAYOPEN;

    /// Enable internal event thread, which makes c-ares spawn its own thread
    /// Simplifies design: No mutexes, no global thread
    int optmask = ARES_OPT_FLAGS | ARES_OPT_EVENT_THREAD;

    if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS)
    {
        ares_library_cleanup();
        throw Exception(ErrorCodes::EXTERNAL_LIBRARY_ERROR, "AsyncAresExecutor(): Failed to initialize the c-ares channel");
    }
}

AsyncAresExecutor::~AsyncAresExecutor()
{
    shutdown();
    ares_library_cleanup();
}

}
