// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2020, The Karbo developers
//
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace CryptoNote {

  using BinaryArray = std::vector<uint8_t>;

  template<class It>
  inline BinaryArray::iterator append(BinaryArray &ba, It be, It en) {
    return ba.insert(ba.end(), be, en);
  }
  inline BinaryArray::iterator append(BinaryArray &ba, size_t add, BinaryArray::value_type va) {
    return ba.insert(ba.end(), add, va);
  }
  inline BinaryArray::iterator append(BinaryArray &ba, const BinaryArray &other) {
    return ba.insert(ba.end(), other.begin(), other.end());
  }

}
