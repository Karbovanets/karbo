// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2019, The Karbo developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <map>
#include <unordered_map>
#include <vector>

#include "BlockchainStorage.h"
#include "Common/StringView.h"
#include "Currency.h"
#include "Difficulty.h"
#include "IBlockchainCache.h"

namespace CryptoNote {

class ISerializer;

struct SpentKeyImage {
  uint32_t blockIndex;
  Crypto::KeyImage keyImage;

  void serialize(ISerializer& s);
};

struct CachedTransactionInfo {
  uint32_t blockIndex;
  uint32_t transactionIndex;
  Crypto::Hash transactionHash;
  uint64_t unlockTime;
  std::vector<TransactionOutputTarget> outputs;
  //needed for getTransactionGlobalIndexes query
  std::vector<uint32_t> globalIndexes;

  void serialize(ISerializer& s);
};

struct OutputGlobalIndexesForAmount {
  uint32_t startIndex = 0;

  // 1. This container must be sorted by PackedOutIndex::blockIndex and PackedOutIndex::transactionIndex
  // 2. GlobalOutputIndex for particular output is calculated as following: startIndex + index in vector
  std::vector<PackedOutIndex> outputs;

  void serialize(ISerializer& s);
};

struct MultisignatureOutputState {
  PackedOutIndex output;
  void serialize(ISerializer& s);
};

struct MultisignatureIndexes {
  uint32_t startIndex = 0;

  // 1. This container must be sorted by PackedOutIndex::blockIndex and PackedOutIndex::transactionIndex
  // 2. GlobalOutputIndex for particular output is calculated as following: startIndex + index in vector
  std::vector<MultisignatureOutputState> outputs;

  void serialize(ISerializer& s);
};

struct PaymentIdTransactionHashPair {
  Crypto::Hash paymentId;
  Crypto::Hash transactionHash;

  void serialize(ISerializer& s);
};

bool serialize(PackedOutIndex& value, Common::StringView name, CryptoNote::ISerializer& serializer);

}
