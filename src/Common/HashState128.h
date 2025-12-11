#pragma once

/// Suppress warnings from xxhash header
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wused-but-marked-unused"
#pragma clang diagnostic ignored "-Wextra-semi-stmt"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wimplicit-fallthrough"

#include <xxHash/xxhash.h>
#include <city.h>

#include <base/defines.h>
#include <base/types.h>
#include <base/extended_types.h>
#include <base/hex.h>
#include <Common/transformEndianness.h>

namespace DB
{

namespace ErrorCodes
{
    extern const int NOT_IMPLEMENTED;
}

}

class HashState128
{
using Hash = CityHash_v1_0_2::uint128;
private:
    Hash hash;

public:
    HashState128() : hash(0, 0) {}

    ALWAYS_INLINE Hash get128() const
    {
      return hash;
    }

    ALWAYS_INLINE UInt64 get64() const
    {
      return hash.low64;
    }

    ALWAYS_INLINE void update(const char * data, UInt64 size)
    {
        const auto first_result = XXH_INLINE_XXH3_128bits(static_cast<const void*>(data), static_cast<size_t>(size));
        /// XOR first result with old hash to get new hash
        hash.high64 ^= first_result.high64;
        hash.low64  ^= first_result.low64;
    }

    template <typename Transform = void, typename T>
    ALWAYS_INLINE void update(const T & x)
    {
        if constexpr (std::endian::native == std::endian::big)
        {
            auto transformed_x = x;
            if constexpr (!std::is_same_v<Transform, void>)
                transformed_x = Transform()(x);
            else
                DB::transformEndianness<std::endian::little>(transformed_x);

            update(reinterpret_cast<const char *>(&transformed_x), sizeof(transformed_x)); /// NOLINT
        }
        else
        {
            update(reinterpret_cast<const char *>(&x), sizeof(x)); /// NOLINT
        }
    }

    ALWAYS_INLINE void update(const std::string & x) { update(x.data(), x.length()); }
    ALWAYS_INLINE void update(const std::string_view x) { update(x.data(), x.size()); }
    ALWAYS_INLINE void update(const char * s) { update(std::string_view(s)); }
};

updateHashFast(const ColumnLowCardinality&  column, HashState128& hash_state);
updateHashFast(const ColumnLazy&            column, HashState128& hash_state);
updateHashFast(const ColumnArray&           column, HashState128& hash_state);
updateHashFast(const ColumnDecimal&         column, HashState128& hash_state);

#pragma clang diagnostic pop
