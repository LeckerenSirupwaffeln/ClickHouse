#pragma once

/// Suppress warnings from xxhash
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wused-but-marked-unused"
#pragma clang diagnostic ignored "-Wextra-semi-stmt"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wimplicit-fallthrough"

#include <string>
#include <utility>

#include <xxHash/xxhash.h>
#include <city.h>

#include <base/defines.h>
#include <base/types.h>
#include <base/extended_types.h>

namespace DB::HashUtils
{

ALWAYS_INLINE UInt128 getFastHash128(const char * data, const size_t size)
{
    const auto result = XXH_INLINE_XXH3_128bits(static_cast<const void *>(data), size);
    const UInt128 output = (static_cast<UInt128>(result.high64) << 64) | static_cast<UInt128>(result.low64);
    return output;
}

ALWAYS_INLINE UInt128 getFastHash128(const std::string& string)
{
    return getFastHash128(string.c_str(), string.size());
}

/// Data structures may have different compiled size across different systems
/// Only pass data structures with a fixed size
template <typename T>
ALWAYS_INLINE UInt128 getFastHash128(const T& x)
{
    return getFastHash128(reinterpret_cast<const char *>(&x), sizeof(x));
}

/// This is a slow way to combine hashes, but it's guaranteed to work well
/// It's slow because we re-calculate hash again
ALWAYS_INLINE UInt128 combineFastHash128(const UInt128 hash_a, const UInt128 hash_b)
{
    constexpr size_t INPUT_WIDTH = sizeof(UInt128);
    static_assert(INPUT_WIDTH == 16, "combineFastHash128() assumes UInt128 is 16 bytes wide");

    char data[INPUT_WIDTH * 2]; /// 256-bits
    memcpy(data,                &hash_a, INPUT_WIDTH);
    memcpy(data + INPUT_WIDTH,  &hash_b, INPUT_WIDTH);

    const UInt128 result = getFastHash128(data, INPUT_WIDTH * 2);
    return result;
}

class HashState128
{
static constexpr UInt128 SEED = 0;

public:
    UInt128 getHash() const { return hash; }

    CityHash_v1_0_2::uint128 getCityHash128() const
    {
        CityHash_v1_0_2::uint128 city_hash;
        city_hash.high64 = this->getHigh64();
        city_hash.low64 = this->getLow64();
        return city_hash;
    }

    UInt64 getLow64() const { return static_cast<UInt64>(hash); }

    UInt64 getHigh64() const { return static_cast<UInt64>(hash >> 64); }

    template <typename... Args>
    void update(Args&&... args)
    {
        const UInt128 next_hash = getFastHash128(std::forward<Args>(args)...);
        hash = combineFastHash128(hash, next_hash);
    }

private:
    UInt128 hash{SEED};
};

#pragma clang diagnostic pop

}
