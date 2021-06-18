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
#include <cstdint>
#include <list>
#include <memory>
#include <system_error>
#include <vector>
#include <utility>

#include <CryptoNote.h>

#include "AddBlockErrors.h"
#include "AddBlockErrorCondition.h"
#include "BlockchainExplorerData.h"
#include "BlockchainMessages.h"
#include "CachedBlock.h"
#include "CachedTransaction.h"
#include "CoreStatistics.h"
#include "Difficulty.h"
#include "ICoreObserver.h"
#include "ICoreDefinitions.h"
#include "MessageQueue.h"
#include "MinerConfig.h"

namespace CryptoNote {

enum class CoreEvent { POOL_UPDATED, BLOCKHAIN_UPDATED };

class ICore {
public:
  virtual ~ICore() {
  }

  virtual bool addMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) = 0;
  virtual bool removeMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) = 0;

  virtual uint32_t getTopBlockIndex() const = 0;
  virtual Crypto::Hash getTopBlockHash() const = 0;
  virtual Crypto::Hash getBlockHashByIndex(uint32_t blockIndex) const = 0;
  virtual uint64_t getBlockTimestampByIndex(uint32_t blockIndex) const = 0;

  virtual bool hasBlock(const Crypto::Hash& blockHash) const = 0;
  virtual BlockTemplate getBlockByIndex(uint32_t index) const = 0;
  virtual BlockTemplate getBlockByHash(const Crypto::Hash& blockHash) const = 0;

  virtual std::vector<Crypto::Hash> buildSparseChain() const = 0;
  virtual std::vector<Crypto::Hash> findBlockchainSupplement(const std::vector<Crypto::Hash>& remoteBlockIds,
                                                             size_t maxCount, uint32_t& totalBlockCount,
                                                             uint32_t& startBlockIndex) const = 0;

  virtual std::vector<RawBlock> getBlocks(uint32_t startIndex, uint32_t count) const = 0;
  virtual void getBlocks(const std::vector<Crypto::Hash>& blockHashes, std::vector<RawBlock>& blocks,
                         std::vector<Crypto::Hash>& missedHashes) const = 0;
  virtual bool queryBlocks(const std::vector<Crypto::Hash>& blockHashes, uint64_t timestamp, uint32_t& startIndex,
                           uint32_t& currentIndex, uint32_t& fullOffset, std::vector<BlockFullInfo>& entries) const = 0;
  virtual bool queryBlocksLite(const std::vector<Crypto::Hash>& knownBlockHashes, uint64_t timestamp,
                               uint32_t& startIndex, uint32_t& currentIndex, uint32_t& fullOffset,
                               std::vector<BlockShortInfo>& entries) const = 0;

  virtual bool hasTransaction(const Crypto::Hash& transactionHash) const = 0;
  virtual bool getTransaction(const Crypto::Hash& transactionHash, BinaryArray& transaction) const = 0;
  virtual void getTransactions(const std::vector<Crypto::Hash>& transactionHashes,
                               std::vector<BinaryArray>& transactions,
                               std::vector<Crypto::Hash>& missedHashes) const = 0;

  virtual Difficulty getBlockDifficulty(uint32_t blockIndex) const = 0;
  virtual Difficulty getBlockCumulativeDifficulty(uint32_t blockIndex) const = 0;

  virtual Difficulty getDifficultyForNextBlock() const = 0;
  virtual Difficulty getAvgDifficulty(uint32_t height, uint32_t window) const = 0;

  virtual std::error_code addBlock(const CachedBlock& cachedBlock, RawBlock&& rawBlock) = 0;
  virtual std::error_code addBlock(RawBlock&& rawBlock) = 0;

  virtual std::error_code submitBlock(BinaryArray&& rawBlockTemplate) = 0;

  virtual bool getTransactionGlobalIndexes(const Crypto::Hash& transactionHash,
                                           std::vector<uint32_t>& globalIndexes) const = 0;
  virtual bool getRandomOutputs(uint64_t amount, uint16_t count, std::vector<uint32_t>& globalIndexes,
                                std::vector<Crypto::PublicKey>& publicKeys) const = 0;

  virtual bool addTransactionToPool(const BinaryArray& transactionBinaryArray) = 0;
  virtual boost::optional<std::pair<MultisignatureOutput, uint64_t>>
  getMultisignatureOutput(uint64_t amount, uint32_t globalIndex) const = 0;

  virtual std::vector<Crypto::Hash> getPoolTransactionHashes() const = 0;
  virtual std::vector<std::pair<Transaction, uint64_t>> getPoolTransactionsWithReceiveTime() const = 0;
  virtual bool getPoolTransaction(const Crypto::Hash& transactionHash, BinaryArray& transaction) const = 0;
  virtual bool getPoolChanges(const Crypto::Hash& lastBlockHash, const std::vector<Crypto::Hash>& knownHashes,
                              std::vector<BinaryArray>& addedTransactions,
                              std::vector<Crypto::Hash>& deletedTransactions) const = 0;
  virtual bool getPoolChangesLite(const Crypto::Hash& lastBlockHash, const std::vector<Crypto::Hash>& knownHashes,
                                  std::vector<TransactionPrefixInfo>& addedTransactions,
                                  std::vector<Crypto::Hash>& deletedTransactions) const = 0;

  virtual bool getBlockTemplate(BlockTemplate& b, const AccountKeys& acc, const BinaryArray& extraNonce, Difficulty& difficulty, uint32_t& height) const = 0;

  virtual CoreStatistics getCoreStatistics() const = 0;

  virtual bool isInCheckpointZone(uint32_t height) const = 0;

  virtual void save() = 0;
  virtual void load(const MinerConfig& minerConfig) = 0;

  virtual bool on_idle() = 0;
  virtual void pauseMining() = 0;
  virtual void updateBlockTemplateAndResumeMining() = 0;
  virtual void onSynchronized() = 0;

  virtual BlockDetails getBlockDetails(const Crypto::Hash& blockHash) const = 0;
  virtual BlockDetails getBlockDetails(const uint32_t blockHeight, const uint32_t attempt = 0) const = 0;
  virtual BlockDetailsShort getBlockDetailsLite(const Crypto::Hash& blockHash) const = 0;
  virtual BlockDetailsShort getBlockDetailsLite(uint32_t blockIndex) const = 0;
  virtual TransactionDetails getTransactionDetails(const Crypto::Hash& transactionHash) const = 0;
  virtual TransactionDetails getTransactionDetails(const Transaction& rawTransaction, const uint64_t timestamp, bool foundInPool) const = 0;
  virtual std::vector<Crypto::Hash> getAlternativeBlockHashesByIndex(uint32_t blockIndex) const = 0;
  virtual std::vector<Crypto::Hash> getBlockHashesByTimestamps(uint64_t timestampBegin, size_t secondsCount) const = 0;
  virtual std::vector<Crypto::Hash> getTransactionHashesByPaymentId(const Crypto::Hash& paymentId) const = 0;
  virtual bool getTransactionsByPaymentId(const Crypto::Hash& paymentId, std::vector<Transaction>& transactions) = 0;
  virtual bool getBlockIndexContainingTransaction(const Crypto::Hash& transactionHash, uint32_t& blockIndex) = 0;

  virtual void rewind(const uint32_t blockIndex) = 0;

  virtual uint64_t getMinimalFee(uint32_t height) = 0;
  virtual uint64_t getMinimalFee() = 0;
  virtual uint64_t calculateReward(uint64_t alreadyGeneratedCoins) const = 0;
  virtual bool getMixin(const Transaction& transaction, uint64_t& mixin) = 0;

  virtual size_t getPoolTransactionsCount() const = 0;
  virtual size_t getBlockchainTransactionsCount() const = 0;
  virtual size_t getAlternativeBlocksCount() const = 0;
  virtual std::vector<Crypto::Hash> getAlternativeBlocksHashes() const = 0;
  virtual uint64_t getTotalGeneratedAmount() const = 0;
  virtual uint32_t getCurrentBlockchainHeight() const = 0;

  virtual bool checkProofOfWork(Crypto::cn_context& context, const CachedBlock& block, Difficulty currentDifficulty) = 0;
  virtual bool getBlockLongHash(Crypto::cn_context &context, const CachedBlock& b, Crypto::Hash& res) = 0;
};
}
