#pragma once

/// Suppress warnings from xxhash header
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wused-but-marked-unused"
#pragma clang diagnostic ignored "-Wextra-semi-stmt"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wimplicit-fallthrough"

#include <xxHash/xxhash.h>

#include <base/defines.h>
#include <base/types.h>
#include <base/extended_types.h>


namespace DB::HashUtils
{

/// Data structures may have different sizes across different systems
/// Only pass blocks of data that are guranteed to have the same size
ALWAYS_INLINE UInt128 getFastHash128(const char * data, size_t size)
{
  /// XXH3 output is always the same regardless of endianness
  const auto result = XXH_INLINE_XXH3_128bits(static_cast<const void *>(data), size);
  /// Bit-shifting numbers is okay regardless of endianness
  const UInt128 output = (static_cast<UInt128>(result.high) << 64) | static_cast<UInt128>(result.low);
  return output;
}

template <typename T>
ALWAYS_INLINE UInt128 getFastHash128(const T& x)
{
    static_assert(std::is_integral_v<T>, "can only call getFastHash128(T) on integral types");
    static_assert(sizeof(T) <= 16, "can only call getFastHash128(T) on integrals 16 bytes or smaller")
    if constexpr (std::endian::native == std::endian::big)
    {
        T transformed_x;
        if constexpr (sizeof(T) == 1)       { transformed_x = x; }
        else if constexpr (sizeof(T) == 2)  { transformed_x = __builtin_bswap_16(x); }
        else if constexpr (sizeof(T) == 4)  { transformed_x = __builtin_bswap_32(x); }
        else if constexpr (sizeof(T) == 8)  { transformed_x = __builtin_bswap_64(x); }
        else if constexpr (sizeof(T) == 16) { transformed_x = __builtin_bswap128(x); }
        else { static_assert(false, "Unsupported integral size for getFastHash128(T)"); }
        return getFastHash128(reinterpret_cast<const char *>(&transformed_x), sizeof(transformed_x));
    }
    else
    {
        return getFastHash128(reinterpret_cast<const char *>(&x), sizeof(x));
    }
}

/// This is a slow way to combine hashes, but it's guaranteed to work well
ALWAYS_INLINE UInt128 combineFastHash128(const UInt128 hash_a, const UInt128 hash_b)
{
  constexpr size_t INPUT_WIDTH = sizeof(UInt128);
  static_assert(INPUT_WIDTH == 16, "combineFastHash128() assumes UInt128 is 16 bytes wide");
  char data[INPUT_WIDTH * 2]; /// 256-bits
  /// We need to preserve the endianness of our input values as a whole
  if constexpr (std::endian::native == std::endian::big)
  {
    memcpy(data,                &hash_a, INPUT_WIDTH);
    memcpy(data + INPUT_WIDTH,  &hash_b, INPUT_WIDTH);
  }
  else
  {
    memcpy(data,                &hash_b, INPUT_WIDTH);
    memcpy(data + INPUT_WIDTH,  &hash_a, INPUT_WIDTH);
  }

  const UInt128 result = getFastHash128(data, INPUT_WIDTH * 2);
  return result;
}

#pragma clang diagnostic pop
