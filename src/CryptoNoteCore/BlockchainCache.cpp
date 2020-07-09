// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2018-2020, The Karbo Developers
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

#include "BlockchainCache.h"

#include <fstream>
#include <tuple>

#include <boost/functional/hash.hpp>

#include "Core.h"
#include "Common/StdInputStream.h"
#include "Common/StdOutputStream.h"
#include "Common/ShuffleGenerator.h"

#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/BlockchainStorage.h"
#include "CryptoNoteCore/TransactionExtra.h"

#include "Serialization/SerializationOverloads.h"
#include "TransactionValidatorState.h"

namespace CryptoNote {

namespace {

UseGenesis addGenesisBlock = UseGenesis(true);
UseGenesis skipGenesisBlock = UseGenesis(false);

template <class T, class F>
void splitGlobalIndexes(T& sourceContainer, T& destinationContainer, uint32_t splitBlockIndex, F lowerBoundFunction) {
  for (auto it = sourceContainer.begin(); it != sourceContainer.end();) {
    auto newCacheOutputsIteratorStart =
        lowerBoundFunction(it->second.outputs.begin(), it->second.outputs.end(), splitBlockIndex);

    auto& indexesForAmount = destinationContainer[it->first];
    auto newCacheOutputsCount =
        static_cast<uint32_t>(std::distance(newCacheOutputsIteratorStart, it->second.outputs.end()));
    indexesForAmount.outputs.reserve(newCacheOutputsCount);

    indexesForAmount.startIndex = it->second.startIndex + static_cast<uint32_t>(it->second.outputs.size()) - newCacheOutputsCount;

    std::move(newCacheOutputsIteratorStart, it->second.outputs.end(), std::back_inserter(indexesForAmount.outputs));
    it->second.outputs.erase(newCacheOutputsIteratorStart, it->second.outputs.end());

    if (indexesForAmount.outputs.empty()) {
      destinationContainer.erase(it->first);
    }

    if (it->second.outputs.empty()) {
      // if we gave all of our outputs we don't need this amount entry any more
      it = sourceContainer.erase(it);
    } else {
      ++it;
    }
  }
}
}

void SpentKeyImage::serialize(ISerializer& s) {
  s(blockIndex, "block_index");
  s(keyImage, "key_image");
}

void CachedTransactionInfo::serialize(ISerializer& s) {
  s(blockIndex, "block_index");
  s(transactionIndex, "transaction_index");
  s(transactionHash, "transaction_hash");
  s(unlockTime, "unlock_time");
  s(outputs, "outputs");
  s(globalIndexes, "global_indexes");
}

void CachedBlockInfo::serialize(ISerializer& s) {
  s(blockHash, "block_hash");
  s(timestamp, "timestamp");
  s(blockSize, "block_size");
  s(cumulativeDifficulty, "cumulative_difficulty");
  s(alreadyGeneratedCoins, "already_generated_coins");
  s(alreadyGeneratedTransactions, "already_generated_transaction_count");
}

void OutputGlobalIndexesForAmount::serialize(ISerializer& s) {
  s(startIndex, "start_index");
  s(outputs, "outputs");
}

void MultisignatureOutputState::serialize(ISerializer& s) {
  s(output, "output");
}

void MultisignatureIndexes::serialize(ISerializer& s) {
  s(startIndex, "start_index");
  s(outputs, "outputs");
}

void PaymentIdTransactionHashPair::serialize(ISerializer& s) {
  s(paymentId, "payment_id");
  s(transactionHash, "transaction_hash");
}

bool serialize(PackedOutIndex& value, Common::StringView name, CryptoNote::ISerializer& serializer) {
  return serializer(value.packedValue, name);
}

}
