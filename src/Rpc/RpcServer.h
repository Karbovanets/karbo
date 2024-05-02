// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016, The Forknote developers
// Copyright (c) 2016-2022, The Karbowanec developers
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

#include "HttpServer.h"

#include <functional>
#include <unordered_map>

#include "Logging/LoggerRef.h"
#include "ITransaction.h"
#include "Common/Math.h"
#include "CoreRpcServerCommandsDefinitions.h"
#include "Rpc/RpcServerConfig.h"
#include "Rpc/JsonRpc.h"

namespace CryptoNote {

class Core;
class NodeServer;
struct ICryptoNoteProtocolHandler;

class RpcServer : public HttpServer {
public:
  RpcServer(RpcServerConfig& config, System::Dispatcher& dispatcher, Logging::ILogger& log, Core& c, NodeServer& p2p, ICryptoNoteProtocolHandler& protocol);

  typedef std::function<bool(RpcServer*, const HttpRequest& request, HttpResponse& response)> HandlerFunction;
  std::vector<std::string> getCorsDomains();
  void run();

private:

  template <class Handler>
  struct RpcHandler {
    const Handler handler;
    const bool allowBusyCore;
  };

  typedef void (RpcServer::*HandlerPtr)(const HttpRequest& request, HttpResponse& response);
  static std::unordered_map<std::string, RpcHandler<HandlerFunction>> s_handlers;

  virtual void processRequest(const HttpRequest& request, HttpResponse& response) override;
  bool processJsonRpcRequest(const HttpRequest& request, HttpResponse& response);

  // binary handlers
  bool onGetBlocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res);
  bool onQueryBlocks(const COMMAND_RPC_QUERY_BLOCKS::request& req, COMMAND_RPC_QUERY_BLOCKS::response& res);
  bool onQueryBlocksLite(const COMMAND_RPC_QUERY_BLOCKS_LITE::request& req, COMMAND_RPC_QUERY_BLOCKS_LITE::response& res);
  bool onGetIndexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res);
  bool onGetRandomOutsBin(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res);
  bool onGetPoolChanges(const COMMAND_RPC_GET_POOL_CHANGES::request& req, COMMAND_RPC_GET_POOL_CHANGES::response& rsp);
  bool onGetPoolChangesLite(const COMMAND_RPC_GET_POOL_CHANGES_LITE::request& req, COMMAND_RPC_GET_POOL_CHANGES_LITE::response& rsp);

  // http handlers
  bool onGetIndex(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res);
  bool onGetSupply(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res);
  bool onGeneratePaymentId(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res);

  // explorer
  bool onGetExplorer(const COMMAND_EXPLORER::request& req, COMMAND_EXPLORER::response& res);
  bool onGetExplorerBlockByHash(const COMMAND_EXPLORER_GET_BLOCK_DETAILS_BY_HASH::request& req, COMMAND_EXPLORER_GET_BLOCK_DETAILS_BY_HASH::response& res);
  bool onGetExplorerTxByHash(const COMMAND_EXPLORER_GET_TRANSACTION_DETAILS_BY_HASH::request& req, COMMAND_EXPLORER_GET_TRANSACTION_DETAILS_BY_HASH::response& res);
  bool onGetExplorerTxsByPaymentId(const COMMAND_EXPLORER_GET_TRANSACTIONS_BY_PAYMENT_ID::request& req, COMMAND_EXPLORER_GET_TRANSACTIONS_BY_PAYMENT_ID::response& res);
  bool onExplorerSearch(const COMMAND_RPC_EXPLORER_SEARCH::request& req, COMMAND_RPC_EXPLORER_SEARCH::response& res);

  // json get handlers
  bool onGetInfo(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res);
  bool onGetHeight(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res);
  bool onGetFeeAddress(const COMMAND_RPC_GET_FEE_ADDRESS::request& req, COMMAND_RPC_GET_FEE_ADDRESS::response& res);
  bool onGetCurrencyId(const COMMAND_RPC_GET_CURRENCY_ID::request& req, COMMAND_RPC_GET_CURRENCY_ID::response& res);
  bool onGetLastBlockHeader(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res);
  bool onGetAltBlocksList(const COMMAND_RPC_GET_ALT_BLOCKS_LIST::request& req, COMMAND_RPC_GET_ALT_BLOCKS_LIST::response& res);
  bool onGetTransactionsPoolShort(const COMMAND_RPC_GET_TRANSACTIONS_POOL_SHORT::request& req, COMMAND_RPC_GET_TRANSACTIONS_POOL_SHORT::response& res);
  bool onGetTransactionsPoolRaw(const COMMAND_RPC_GET_RAW_TRANSACTIONS_POOL::request& req, COMMAND_RPC_GET_RAW_TRANSACTIONS_POOL::response& res);
  bool onGetTransactionsPool(const COMMAND_RPC_GET_TRANSACTIONS_POOL::request& req, COMMAND_RPC_GET_TRANSACTIONS_POOL::response& res);

  // json post handlers
  bool onGetBlocksDetailsByHeights(const COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS::request& req, COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS::response& rsp);
  bool onGetBlocksDetailsByHashes(const COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES::request& req, COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES::response& rsp);
  bool onGetBlocksHashesByTimestamps(const COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS::request& req, COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS::response& rsp);
  bool onGetTransactionDetailsByHashes(const COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASHES::request& req, COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASHES::response& rsp);
  bool onGetTransactionDetailsByHash(const COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::request& req, COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::response& rsp);
  bool onGetTransactionDetailsByHeights(const COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HEIGHTS::request& req, COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HEIGHTS::response& rsp);
  bool onGetTransactionsWithOutputGlobalIndexesByHeights(const COMMAND_RPC_GET_TRANSACTIONS_WITH_OUTPUT_GLOBAL_INDEXES_BY_HEIGHTS::request& req, COMMAND_RPC_GET_TRANSACTIONS_WITH_OUTPUT_GLOBAL_INDEXES_BY_HEIGHTS::response& rsp);
  bool onGetTransactionHashesByPaymentId(const COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::request& req, COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::response& rsp);
  bool onGetTransactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res);
  bool onGetRandomOutsJson(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_JSON::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_JSON::response& res);
  bool onSendRawTx(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res);
  bool onGetBlockCount(const COMMAND_RPC_GETBLOCKCOUNT::request& req, COMMAND_RPC_GETBLOCKCOUNT::response& res);
  bool onGetBlockHash(const COMMAND_RPC_GETBLOCKHASH::request& req, COMMAND_RPC_GETBLOCKHASH::response& res);
  bool onGetBlockTemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& req, COMMAND_RPC_GETBLOCKTEMPLATE::response& res);
  bool onSubmitBlock(const COMMAND_RPC_SUBMITBLOCK::request& req, COMMAND_RPC_SUBMITBLOCK::response& res);
  bool onGetBocksList(const COMMAND_RPC_GET_BLOCKS_LIST::request& req, COMMAND_RPC_GET_BLOCKS_LIST::response& res);
  bool onGetBlockHeaderByHash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res);
  bool onGetBlockHeaderByHeight(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res);
  bool onGetBlockTimestampByHeight(const COMMAND_RPC_GET_BLOCK_TIMESTAMP_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_TIMESTAMP_BY_HEIGHT::response& res);
  bool onGetBlockDetailsByHeight(const COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::response& res);
  bool onGetBlockDetailsByHash(const COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::response& res);
  bool onGetTransactionsByPaymentId(const COMMAND_RPC_GET_TRANSACTIONS_BY_PAYMENT_ID::request& req, COMMAND_RPC_GET_TRANSACTIONS_BY_PAYMENT_ID::response& res);
  bool onCheckTxSecretKey(const COMMAND_RPC_CHECK_TX_KEY::request& req, COMMAND_RPC_CHECK_TX_KEY::response& res);
  bool onCheckTxWithViewKey(const COMMAND_RPC_CHECK_TX_WITH_PRIVATE_VIEW_KEY::request& req, COMMAND_RPC_CHECK_TX_WITH_PRIVATE_VIEW_KEY::response& res);
  bool onCheckTxProof(const COMMAND_RPC_CHECK_TX_PROOF::request& req, COMMAND_RPC_CHECK_TX_PROOF::response& res);
  bool onCheckReserveProof(const COMMAND_RPC_CHECK_RESERVE_PROOF::request& req, COMMAND_RPC_CHECK_RESERVE_PROOF::response& res);
  bool onValidateAddress(const COMMAND_RPC_VALIDATE_ADDRESS::request& req, COMMAND_RPC_VALIDATE_ADDRESS::response& res);
  bool onVerifyMessage(const COMMAND_RPC_VERIFY_MESSAGE::request& req, COMMAND_RPC_VERIFY_MESSAGE::response& res);
  bool onResolveOpenAlias(const COMMAND_RPC_RESOLVE_OPEN_ALIAS::request& req, COMMAND_RPC_RESOLVE_OPEN_ALIAS::response& res);
  bool onCheckPayment(const COMMAND_RPC_CHECK_PAYMENT_BY_PAYMENT_ID::request& req, COMMAND_RPC_CHECK_PAYMENT_BY_PAYMENT_ID::response& rsp);

  // disabled in restricted rpc mode
  bool onStopDaemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res);
  bool onGetPeerList(const COMMAND_RPC_GET_PEER_LIST::request& req, COMMAND_RPC_GET_PEER_LIST::response& res);
  bool onGetConnections(const COMMAND_RPC_GET_CONNECTIONS::request& req, COMMAND_RPC_GET_CONNECTIONS::response& res);


  void fillBlockHeaderResponse(const BlockTemplate& blk, bool orphan_status, uint32_t index, const Crypto::Hash& hash, block_header_response& responce);
  void fillTransactionsWithOutputGlobalIndexesByHeights(uint32_t start_height, uint32_t count, bool include_miner_txs, std::vector<tx_with_output_global_indexes>& transactions);

  RawBlockLegacy prepareRawBlockLegacy(BinaryArray&& blockBlob);
  bool isCoreReady();
  bool checkIncomingTransactionForFee(const BinaryArray& tx_blob);

  RpcServerConfig m_config;
  Logging::LoggerRef logger;
  Core& m_core;
  NodeServer& m_p2p;
  ICryptoNoteProtocolHandler& m_protocol;

  std::string m_fee_address;
  uint64_t    m_fee_amount;
  std::string m_contact_info;
  AccountPublicAddress m_fee_acc;
  Crypto::SecretKey m_view_key = NULL_SECRET_KEY;
  bool m_restricted_rpc;
  std::vector<std::string> m_cors_domains;

};

}
