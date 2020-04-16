// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
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

#pragma once

#include "INode.h"
#include "ITransaction.h"
#include "CryptoNoteProtocol/ICryptoNoteProtocolObserver.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandlerCommon.h"
#include "CryptoNoteCore/BlockchainMessages.h"
#include "CryptoNoteCore/ICore.h"
#include "CryptoNoteCore/ICoreObserver.h"
#include "CryptoNoteCore/MessageQueue.h"
#include "Common/ObserverManager.h"

#include "System/ContextGroup.h"
#include "System/Dispatcher.h"

#include <atomic>
#include <thread>
#include <boost/asio.hpp>

namespace CryptoNote {

class core;

class InProcessNode : public INode, public CryptoNote::ICryptoNoteProtocolObserver {
public:
  //NOTE: dispatcher must be the same as the one used in core and protocol
  InProcessNode(CryptoNote::ICore& core, CryptoNote::ICryptoNoteProtocolHandler& protocol, System::Dispatcher& dispatcher);

  InProcessNode(const InProcessNode&) = delete;
  InProcessNode(InProcessNode&&) = delete;

  InProcessNode& operator=(const InProcessNode&) = delete;
  InProcessNode& operator=(InProcessNode&&) = delete;

  virtual ~InProcessNode() override;

  //precondition: must be called in dispatcher's thread
  virtual void init(const Callback& callback) override;
  //precondition: must be called in dispatcher's thread
  virtual bool shutdown() override;

  virtual bool addObserver(INodeObserver* observer) override;
  virtual bool removeObserver(INodeObserver* observer) override;

  //precondition: all of following methods must not be invoked in dispatcher's thread
  virtual size_t getPeerCount() const override;
  virtual uint32_t getLastLocalBlockHeight() const override;
  virtual uint32_t getLastKnownBlockHeight() const override;
  virtual uint32_t getLocalBlockCount() const override;
  virtual uint32_t getKnownBlockCount() const override;
  virtual uint32_t getNodeHeight() const override;
  virtual uint64_t getLastLocalBlockTimestamp() const override;
  virtual uint64_t getMinimalFee() const override;
  virtual uint64_t getNextDifficulty() const override;
  virtual uint64_t getNextReward() const override;
  virtual uint64_t getAlreadyGeneratedCoins() const override;
  virtual uint64_t getTransactionsCount() const override;
  virtual uint64_t getTransactionsPoolSize() const override;
  virtual uint64_t getAltBlocksCount() const override;
  virtual uint64_t getOutConnectionsCount() const override;
  virtual uint64_t getIncConnectionsCount() const override;
  virtual uint64_t getRpcConnectionsCount() const override;
  virtual uint64_t getWhitePeerlistSize() const override;
  virtual uint64_t getGreyPeerlistSize() const override;
  virtual std::string getNodeVersion() const override;
  virtual std::string feeAddress() const override { return std::string(); }
  virtual uint64_t feeAmount() const override { return 0; }

  virtual void getBlockHashesByTimestamps(uint64_t timestampBegin, size_t secondsCount, std::vector<Crypto::Hash>& blockHashes, const Callback& callback) override;
  virtual void getTransactionHashesByPaymentId(const Crypto::Hash& paymentId, std::vector<Crypto::Hash>& transactionHashes, const Callback& callback) override;

  virtual BlockHeaderInfo getLastLocalBlockHeaderInfo() const override;

  virtual void getNewBlocks(std::vector<Crypto::Hash>&& knownBlockIds, std::vector<RawBlock>& newBlocks, uint32_t& startHeight, const Callback& callback) override;
  virtual void getTransactionOutsGlobalIndices(const Crypto::Hash& transactionHash, std::vector<uint32_t>& outsGlobalIndices, const Callback& callback) override;
  virtual void getRandomOutsByAmounts(std::vector<uint64_t>&& amounts, uint16_t outsCount,
      std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount>& result, const Callback& callback) override;
  virtual void relayTransaction(const CryptoNote::Transaction& transaction, const Callback& callback) override;
  virtual void queryBlocks(std::vector<Crypto::Hash>&& knownBlockIds, uint64_t timestamp, std::vector<BlockShortEntry>& newBlocks,
    uint32_t& startHeight, const Callback& callback) override;
  virtual void getPoolSymmetricDifference(std::vector<Crypto::Hash>&& knownPoolTxIds, Crypto::Hash knownBlockId, bool& isBcActual,
          std::vector<std::unique_ptr<ITransactionReader>>& newTxs, std::vector<Crypto::Hash>& deletedTxIds, const Callback& callback) override;
  virtual void getMultisignatureOutputByGlobalIndex(uint64_t amount, uint32_t gindex, MultisignatureOutput& out, const Callback& callback) override;

  virtual void getBlocks(const std::vector<uint32_t>& blockHeights, std::vector<std::vector<BlockDetails>>& blocks, const Callback& callback) override;
  virtual void getBlocks(const std::vector<Crypto::Hash>& blockHashes, std::vector<BlockDetails>& blocks, const Callback& callback) override;
  virtual void getBlock(const uint32_t blockHeight, BlockDetails &block, const Callback& callback) override;
  virtual void getBlockTimestamp(uint32_t height, uint64_t& timestamp, const Callback& callback) override;
  virtual void getTransaction(const Crypto::Hash& transactionHash, CryptoNote::Transaction& transaction, const Callback& callback) override;
  virtual void getTransactions(const std::vector<Crypto::Hash>& transactionHashes, std::vector<TransactionDetails>& transactions, const Callback& callback) override;
  virtual void getTransactionsByPaymentId(const Crypto::Hash& paymentId, std::vector<TransactionDetails>& transactions, const Callback& callback) override;
  virtual void isSynchronized(bool& syncStatus, const Callback& callback) override;
  virtual void getConnections(std::vector<p2pConnection>& connections, const Callback& callback) override;

private:
  virtual void peerCountUpdated(size_t count) override;
  virtual void lastKnownBlockHeightUpdated(uint32_t height) override;
  virtual void blockchainSynchronized(uint32_t topHeight) override;
  void blockchainUpdated(uint32_t topBlockIndex);
  void chainSwitched(uint32_t topBlockIndex, uint32_t commonRoot, const std::vector<Crypto::Hash>& hashes);
  void poolUpdated();

  void executeInRemoteThread(std::function<void()>&& func);
  void executeInDispatcherThread(std::function<void()>&& func);
  void updateLastLocalBlockHeaderInfo();
  void resetLastLocalBlockHeaderInfo();

  std::error_code doGetNewBlocks(const std::vector<Crypto::Hash>& knownBlockIds, std::vector<CryptoNote::RawBlock>& newBlocks, uint32_t& startHeight);
  std::error_code doGetTransactionOutsGlobalIndices(const Crypto::Hash& transactionHash, std::vector<uint32_t>& outsGlobalIndices);
  std::error_code doGetRandomOutsByAmounts(std::vector<uint64_t>&& amounts, uint16_t outsCount,
      std::vector<CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount>& result);
  std::error_code doRelayTransaction(const CryptoNote::Transaction& transaction);
  std::error_code doQueryBlocksLite(std::vector<Crypto::Hash>&& knownBlockIds, uint64_t timestamp, std::vector<BlockShortEntry>& newBlocks, uint32_t& startHeight);
  std::error_code doGetOutputByMultisigGlobalIndex(uint64_t amount, uint32_t gindex, MultisignatureOutput& out);
  std::error_code doGetBlocks(const std::vector<uint32_t>& blockHeights, std::vector<std::vector<BlockDetails>>& blocks);
  std::error_code doGetBlocks(const std::vector<Crypto::Hash>& blockHashes, std::vector<BlockDetails>& blocks);
  std::error_code doGetBlockTimestamp(uint32_t height, uint64_t& timestamp);
  std::error_code doGetTransaction(const Crypto::Hash& transactionHash, CryptoNote::Transaction& transaction);
  std::error_code doGetTransactions(const std::vector<Crypto::Hash>& transactionHashes, std::vector<TransactionDetails>& transactions);
  std::error_code doGetTransactionsByPaymentId(const Crypto::Hash& paymentId, std::vector<TransactionDetails>& transactions);
  std::error_code doGetPoolSymmetricDifference(std::vector<Crypto::Hash>&& knownPoolTxIds, Crypto::Hash knownBlockId,
    bool& isBcActual, std::vector<std::unique_ptr<ITransactionReader>>& newTxs, std::vector<Crypto::Hash>& deletedTxIds);
  std::error_code doGetConnections(std::vector<p2pConnection>& connections);

  bool doShutdown();

  enum State {
    NOT_INITIALIZED,
    INITIALIZED
  };

  State state;
  System::Dispatcher& dispatcher;
  mutable std::atomic<size_t> contextCounter;
  mutable System::Event contextCounterEvent;
  System::ContextGroup contextGroup;

  //precondition: any call to core's methods must be performed from user dispatcher's thread
  CryptoNote::ICore& core;
  //precondition: any call to protocol's methods must be performed from user dispatcher's thread
  CryptoNote::ICryptoNoteProtocolHandler& protocol;
  Tools::ObserverManager<INodeObserver> observerManager;
  BlockHeaderInfo lastLocalBlockHeaderInfo;

  MessageQueue<BlockchainMessage> messageQueue;

  mutable std::mutex mutex;
};

} //namespace CryptoNote
