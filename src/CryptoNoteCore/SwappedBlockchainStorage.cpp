// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2016-2020, The Karbo developers
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

#include "SwappedBlockchainStorage.h"

#include <cassert>

#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "ICoreDefinitions.h"
#include "MemoryBlockchainStorage.h"
#include "Serialization/SerializationOverloads.h"

namespace CryptoNote {

SwappedBlockchainStorage::SwappedBlockchainStorage(const std::string& indexFileName, const std::string& dataFileName) {
  if (!blocks.open(dataFileName, indexFileName, 1024)) {
    throw std::runtime_error("Can't open blockchain storage files.");
  }
}

SwappedBlockchainStorage::~SwappedBlockchainStorage() {
  blocks.close();
}

void SwappedBlockchainStorage::pushBlock(RawBlock&& rawBlock) {
  blocks.push_back(rawBlock);
}

RawBlock SwappedBlockchainStorage::getBlockByIndex(uint32_t index) const {
  if (index >= getBlockCount()) {
    throw std::out_of_range("SwappedBlockchainStorage, index < blockCount!");
  }

  return blocks[index];
}

uint32_t SwappedBlockchainStorage::getBlockCount() const {
  return static_cast<uint32_t>(blocks.size());
}

//Returns MemoryBlockchainStorage with elements from [splitIndex, blocks.size() - 1].
//Original SwappedBlockchainStorage will contain elements from [0, splitIndex - 1].
std::unique_ptr<BlockchainStorage::IBlockchainStorageInternal> SwappedBlockchainStorage::splitStorage(uint32_t splitIndex) {
  assert(splitIndex > 0);
  assert(splitIndex < blocks.size());
  std::unique_ptr<MemoryBlockchainStorage> newStorage = std::unique_ptr<MemoryBlockchainStorage>(new MemoryBlockchainStorage(splitIndex));

  uint64_t blocksCount = blocks.size();

  for (uint64_t i = splitIndex; i < blocksCount; ++i) {
    newStorage->pushBlock(RawBlock(blocks[i]));
  }

  for (uint64_t i = 0; i < blocksCount - splitIndex; ++i) {
    blocks.pop_back();
  }

  return newStorage;
}

}
