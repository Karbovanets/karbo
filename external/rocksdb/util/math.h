//  Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#pragma once

#include <assert.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace ROCKSDB_NAMESPACE {

#if defined(_MSC_VER) && !defined(_M_X64)
namespace detail {
template <typename T>
int BitsSetToOneFallback(T v) {
  const int kBits = static_cast<int>(sizeof(T)) * 8;
  static_assert((kBits & (kBits - 1)) == 0, "must be power of two bits");
  // we static_cast these bit patterns in order to truncate them to the correct
  // size
  v = static_cast<T>(v - ((v >> 1) & static_cast<T>(0x5555555555555555ull)));
  v = static_cast<T>((v & static_cast<T>(0x3333333333333333ull)) +
                     ((v >> 2) & static_cast<T>(0x3333333333333333ull)));
  v = static_cast<T>((v + (v >> 4)) & static_cast<T>(0x0F0F0F0F0F0F0F0Full));
  for (int shift_bits = 8; shift_bits < kBits; shift_bits <<= 1) {
    v += static_cast<T>(v >> shift_bits);
  }
  // we want the bottom "slot" that's big enough to represent a value up to
  // (and including) kBits.
  return static_cast<int>(v & static_cast<T>(kBits | (kBits - 1)));
}

}  // namespace detail
#endif

// Number of bits set to 1. Also known as "population count".
template <typename T>
inline int BitsSetToOne(T v) {
  static_assert(std::is_integral<T>::value, "non-integral type");
#ifdef _MSC_VER
  static_assert(sizeof(T) <= sizeof(uint64_t), "type too big");
  if (sizeof(T) < sizeof(uint32_t)) {
    // This bit mask is to avoid a compiler warning on unused path
    constexpr auto mm = 8 * sizeof(uint32_t) - 1;
    // The bit mask is to neutralize sign extension on small signed types
    constexpr uint32_t m = (uint32_t{1} << ((8 * sizeof(T)) & mm)) - 1;
#if defined(_M_X64) || defined(_M_IX86)
    return static_cast<int>(__popcnt(static_cast<uint32_t>(v) & m));
#else
    return static_cast<int>(detail::BitsSetToOneFallback(v) & m);
#endif
  } else if (sizeof(T) == sizeof(uint32_t)) {
#if defined(_M_X64) || defined(_M_IX86)
    return static_cast<int>(__popcnt(static_cast<uint32_t>(v)));
#else
    return detail::BitsSetToOneFallback(static_cast<uint32_t>(v));
#endif
  } else {
#ifdef _M_X64
    return static_cast<int>(__popcnt64(static_cast<uint64_t>(v)));
#elif defined(_M_IX86)
    return static_cast<int>(
        __popcnt(static_cast<uint32_t>(static_cast<uint64_t>(v) >> 32) +
                 __popcnt(static_cast<uint32_t>(v))));
#else
    return detail::BitsSetToOneFallback(static_cast<uint64_t>(v));
#endif
  }
#else
  static_assert(sizeof(T) <= sizeof(unsigned long long), "type too big");
  if (sizeof(T) < sizeof(unsigned int)) {
    // This bit mask is to avoid a compiler warning on unused path
    constexpr auto mm = 8 * sizeof(unsigned int) - 1;
    // This bit mask is to neutralize sign extension on small signed types
    constexpr unsigned int m = (1U << ((8 * sizeof(T)) & mm)) - 1;
    return __builtin_popcount(static_cast<unsigned int>(v) & m);
  } else if (sizeof(T) == sizeof(unsigned int)) {
    return __builtin_popcount(static_cast<unsigned int>(v));
  } else if (sizeof(T) <= sizeof(unsigned long)) {
    return __builtin_popcountl(static_cast<unsigned long>(v));
  } else {
    return __builtin_popcountll(static_cast<unsigned long long>(v));
  }
#endif
}

}  // namespace ROCKSDB_NAMESPACE
