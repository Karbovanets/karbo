// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2016, The Forknote developers
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

#include "RpcServer.h"
#include "cnVersion.h"

#include <future>
#include <unordered_map>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>

// CryptoNote
#include "crypto/random.h"
#include "Common/Base58.h"
#include "Common/Math.h"
#include "Common/StringTools.h"
#include "CryptoNoteCore/TransactionUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteCore/TransactionUtils.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandlerCommon.h"
#include "CryptoNoteProtocol/ICryptoNoteProtocolQuery.h"
#include "P2p/ConnectionContext.h"
#include "P2p/NetNode.h"

#include "CoreRpcServerErrorCodes.h"
#include "JsonRpc.h"

#undef ERROR

using namespace Logging;
using namespace Crypto;
using namespace Common;

const uint64_t BLOCK_LIST_MAX_COUNT = 1000;

namespace CryptoNote {

static inline void serialize(COMMAND_RPC_GET_BLOCKS_FAST::response& response, ISerializer &s) {
  KV_MEMBER(response.blocks)
  KV_MEMBER(response.start_height)
  KV_MEMBER(response.current_height)
  KV_MEMBER(response.status)
}

void serialize(BlockFullInfo& blockFullInfo, ISerializer& s) {
  KV_MEMBER(blockFullInfo.block_id);
  KV_MEMBER(blockFullInfo.block);
  s(blockFullInfo.transactions, "txs");
}

void serialize(TransactionPrefixInfo& transactionPrefixInfo, ISerializer& s) {
  KV_MEMBER(transactionPrefixInfo.txHash);
  KV_MEMBER(transactionPrefixInfo.txPrefix);
}

void serialize(BlockShortInfo& blockShortInfo, ISerializer& s) {
  KV_MEMBER(blockShortInfo.blockId);
  KV_MEMBER(blockShortInfo.block);
  KV_MEMBER(blockShortInfo.txPrefixes);
}

namespace {

template <typename Command>
RpcServer::HandlerFunction binMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromBinaryKeyValue(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    response.setBody(storeToBinaryKeyValue(res.data()));
    return result;
  };
}

template <typename Command>
RpcServer::HandlerFunction jsonMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromJson(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    for (const auto &cors_domain : obj->getCorsDomains()) {
      if (!cors_domain.empty()) {
        response.addHeader("Access-Control-Allow-Origin", cors_domain);
        response.addHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
        response.addHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
      }
    }
    response.addHeader("Content-Type", "application/json");
    response.setBody(storeToJson(res.data()));
    return result;
  };
}

template <typename Command>
RpcServer::HandlerFunction httpMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromJson(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);

    for (const auto &cors_domain : obj->getCorsDomains()) {
      if (!cors_domain.empty()) {
        response.addHeader("Access-Control-Allow-Origin", cors_domain);
        response.addHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
        response.addHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
      }
    }
    response.addHeader("Content-Type", "text/html; charset=UTF-8");
    response.addHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    response.addHeader("Expires", "0");
    response.setStatus(HttpResponse::HTTP_STATUS::STATUS_200);

    response.setBody(res);

    return result;
  };
}

}
  
std::unordered_map<std::string, RpcServer::RpcHandler<RpcServer::HandlerFunction>> RpcServer::s_handlers = {
  
  // binary handlers
  { "/getblocks.bin", { binMethod<COMMAND_RPC_GET_BLOCKS_FAST>(&RpcServer::onGetBlocks), false } },
  { "/queryblocks.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS>(&RpcServer::onQueryBlocks), false } },
  { "/queryblockslite.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS_LITE>(&RpcServer::onQueryBlocksLite), false } },
  { "/get_o_indexes.bin", { binMethod<COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES>(&RpcServer::onGetIndexes), false } },
  { "/getrandom_outs.bin", { binMethod<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS>(&RpcServer::onGetRandomOuts), false } },
  { "/get_pool_changes.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES>(&RpcServer::onGetPoolChanges), false } },
  { "/get_pool_changes_lite.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES_LITE>(&RpcServer::onGetPoolChangesLite), false } },
  { "/get_blocks_details_by_hashes.bin", { binMethod<COMMAND_RPC_BIN_GET_BLOCKS_DETAILS_BY_HASHES>(&RpcServer::onBinGetBlocksDetailsByHashes), false } },
  { "/get_blocks_details_by_heights.bin", { binMethod<COMMAND_RPC_BIN_GET_BLOCKS_DETAILS_BY_HEIGHTS>(&RpcServer::onBinGetBlocksDetailsByHeights), false } },
  { "/get_blocks_hashes_by_timestamps.bin", { binMethod<COMMAND_RPC_BIN_GET_BLOCKS_HASHES_BY_TIMESTAMPS>(&RpcServer::onBinGetBlocksHashesByTimestamps), false } },
  { "/get_transaction_details_by_hashes.bin", { binMethod<COMMAND_RPC_BIN_GET_TRANSACTION_DETAILS_BY_HASHES>(&RpcServer::onBinGetTransactionDetailsByHashes), false } },
  { "/get_transaction_hashes_by_payment_id.bin", { binMethod<COMMAND_RPC_BIN_GET_TRANSACTION_HASHES_BY_PAYMENT_ID>(&RpcServer::onBinGetTransactionHashesByPaymentId), false } },

  // http handlers
  { "/", { httpMethod<COMMAND_HTTP>(&RpcServer::onGetIndex), true } },
  { "/supply", { httpMethod<COMMAND_HTTP>(&RpcServer::onGetSupply), false } },
  { "/paymentid", { httpMethod<COMMAND_HTTP>(&RpcServer::onGeneratePaymentId), true } },

  // http get json handlers
  { "/getinfo", { jsonMethod<COMMAND_RPC_GET_INFO>(&RpcServer::onGetInfo), true } },
  { "/getheight", { jsonMethod<COMMAND_RPC_GET_HEIGHT>(&RpcServer::onGetHeight), true } },
  { "/feeaddress", { jsonMethod<COMMAND_RPC_GET_FEE_ADDRESS>(&RpcServer::onGetFeeAddress), true } },
  
  // disabled in restricted rpc mode
  { "/getpeers", { jsonMethod<COMMAND_RPC_GET_PEER_LIST>(&RpcServer::onGetPeerList), true } },
  { "/stop_daemon", { jsonMethod<COMMAND_RPC_STOP_DAEMON>(&RpcServer::onStopDaemon), true } },
  { "/getconnections", { jsonMethod<COMMAND_RPC_GET_CONNECTIONS>(&RpcServer::onGetConnections), true } },

  // rpc post json handlers
  { "/gettransactions", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS>(&RpcServer::onGetTransactions), false } },
  { "/sendrawtransaction", { jsonMethod<COMMAND_RPC_SEND_RAW_TX>(&RpcServer::onSendRawTx), false } },
  { "/getblocks", { jsonMethod<COMMAND_RPC_GET_BLOCKS_FAST>(&RpcServer::onGetBlocks), false } },
  { "/queryblocks", { jsonMethod<COMMAND_RPC_QUERY_BLOCKS>(&RpcServer::onQueryBlocks), false } },
  { "/queryblockslite", { jsonMethod<COMMAND_RPC_QUERY_BLOCKS_LITE>(&RpcServer::onQueryBlocksLite), false } },
  { "/get_o_indexes", { jsonMethod<COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES>(&RpcServer::onGetIndexes), false } },
  { "/getrandom_outs", { jsonMethod<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS>(&RpcServer::onGetRandomOuts), false } },
  { "/get_pool_changes", { jsonMethod<COMMAND_RPC_GET_POOL_CHANGES>(&RpcServer::onGetPoolChanges), false } },
  { "/get_pool_changes_lite", { jsonMethod<COMMAND_RPC_GET_POOL_CHANGES_LITE>(&RpcServer::onGetPoolChangesLite), false } },
  { "/get_block_details_by_height", { jsonMethod<COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT>(&RpcServer::onGetBlockDetailsByHeight), false } },
  { "/get_block_details_by_hash", { jsonMethod<COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH>(&RpcServer::onGetBlockDetailsByHash), true } },
  { "/get_blocks_details_by_heights", { jsonMethod<COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS>(&RpcServer::onGetBlocksDetailsByHeights), false } },
  { "/get_blocks_details_by_hashes", { jsonMethod<COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES>(&RpcServer::onGetBlocksDetailsByHashes), false } },
  { "/get_blocks_hashes_by_timestamps", { jsonMethod<COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS>(&RpcServer::onGetBlocksHashesByTimestamps), false } },
  { "/get_transaction_details_by_hashes", { jsonMethod<COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASHES>(&RpcServer::onGetTransactionDetailsByHashes), false } },
  { "/get_transaction_details_by_hash", { jsonMethod<COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH>(&RpcServer::onGetTransactionDetailsByHash), true } },
  { "/get_transaction_hashes_by_payment_id", { jsonMethod<COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID>(&RpcServer::onGetTransactionHashesByPaymentId), false } },

  // json rpc
  { "/json_rpc", { std::bind(&RpcServer::processJsonRpcRequest, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), true } }
};

RpcServer::RpcServer(System::Dispatcher& dispatcher, Logging::ILogger& log, Core& c, NodeServer& p2p, ICryptoNoteProtocolHandler& protocol) :
  HttpServer(dispatcher, log), logger(log, "RpcServer"), m_core(c), m_p2p(p2p), m_protocol(protocol) {
}

void RpcServer::processRequest(const HttpRequest& request, HttpResponse& response) {

  try {

  auto url = request.getUrl();
  if (url.find(".bin") == std::string::npos) {
      logger(TRACE) << "RPC request came: \n" << request << std::endl;
  } else {
      logger(TRACE) << "RPC request came: " << url << std::endl;
  }

  auto it = s_handlers.find(url);
  if (it == s_handlers.end()) {
    if (Common::starts_with(url, "/api/")) {

      std::string block_height_method = "/api/block/height/";
      std::string block_hash_method = "/api/block/hash/";
      std::string tx_hash_method = "/api/transaction/";
      std::string payment_id_method = "/api/payment_id/";

      if (Common::starts_with(url, block_height_method)) {

        std::string height_str = url.substr(block_height_method.size());
        uint32_t height = Common::integer_cast<uint32_t>(height_str);
        auto it = s_handlers.find("/get_block_details_by_height");
        if (!it->second.allowBusyCore && !isCoreReady()) {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Core is busy");
          return;
        }
        COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::request req;
        req.blockHeight = height;
        COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::response rsp;
        bool r = onGetBlockDetailsByHeight(req, rsp);
        if (r) {
          response.addHeader("Content-Type", "application/json");
          response.setStatus(HttpResponse::HTTP_STATUS::STATUS_200);
          response.setBody(storeToJson(rsp));
        }
        else {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Internal error");
        }
        return;

      }
      else if (Common::starts_with(url, block_hash_method)) {

        std::string hash_str = url.substr(block_hash_method.size());
        auto it = s_handlers.find("/get_block_details_by_hash");
        if (!it->second.allowBusyCore && !isCoreReady()) {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Core is busy");
          return;
        }
        COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::request req;
        req.hash = hash_str;
        COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::response rsp;
        bool r = onGetBlockDetailsByHash(req, rsp);
        if (r) {
          response.addHeader("Content-Type", "application/json");
          response.setStatus(HttpResponse::HTTP_STATUS::STATUS_200);
          response.setBody(storeToJson(rsp));
        }
        else {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Internal error");
        }
        return;

      }
      else if (Common::starts_with(url, tx_hash_method)) {

        std::string hash_str = url.substr(tx_hash_method.size());
        auto it = s_handlers.find("/get_transaction_details_by_hash");
        if (!it->second.allowBusyCore && !isCoreReady()) {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Core is busy");
          return;
        }
        COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::request req;
        req.hash = hash_str;
        COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::response rsp;
        bool r = onGetTransactionDetailsByHash(req, rsp);
        if (r) {
          response.addHeader("Content-Type", "application/json");
          response.setStatus(HttpResponse::HTTP_STATUS::STATUS_200);
          response.setBody(storeToJson(rsp));
        }
        else {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Internal error");
        }
        return;

      }
      else if (Common::starts_with(url, payment_id_method)) {

        std::string pid_str = url.substr(payment_id_method.size());
        auto it = s_handlers.find("/get_transaction_hashes_by_payment_id");
        if (!it->second.allowBusyCore && !isCoreReady()) {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Core is busy");
          return;
        }
        COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::request req;
        req.paymentId = pid_str;
        COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::response rsp;
        bool r = onGetTransactionHashesByPaymentId(req, rsp);
        if (r) {
          response.addHeader("Content-Type", "application/json");
          response.setStatus(HttpResponse::HTTP_STATUS::STATUS_200);
          response.setBody(storeToJson(rsp));
        }
        else {
          response.setStatus(HttpResponse::STATUS_500);
          response.setBody("Internal error");
        }
        return;

      }
      response.setStatus(HttpResponse::STATUS_404);
      return;
    }
    else {
      response.setStatus(HttpResponse::STATUS_404);
      return;
    }
  }

  if (!it->second.allowBusyCore && !isCoreReady()) {
    response.setStatus(HttpResponse::STATUS_500);
    response.setBody("Core is busy");
    return;
  }

  it->second.handler(this, request, response);

  }
  catch (const JsonRpc::JsonRpcError& err) {
    response.addHeader("Content-Type", "application/json");
    response.setStatus(HttpResponse::STATUS_500);
    response.setBody(storeToJsonValue(err).toString());
  }
  catch (const std::exception& e) {
    response.setStatus(HttpResponse::STATUS_500);
    response.setBody(e.what());
  }
}

bool RpcServer::processJsonRpcRequest(const HttpRequest& request, HttpResponse& response) {

  using namespace JsonRpc;

  response.addHeader("Content-Type", "application/json");
  for (const auto& cors_domain: m_cors_domains) {
    if (!cors_domain.empty()) {
      response.addHeader("Access-Control-Allow-Origin", cors_domain);
      response.addHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
      response.addHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    }
  }

  JsonRpcRequest jsonRequest;
  JsonRpcResponse jsonResponse;

  try {
    logger(TRACE) << "JSON-RPC request: " << request.getBody();
    jsonRequest.parseRequest(request.getBody());
    jsonResponse.setId(jsonRequest.getId()); // copy id

    static std::unordered_map<std::string, RpcServer::RpcHandler<JsonMemberMethod>> jsonRpcHandlers = {

      { "getblockcount", { makeMemberMethod(&RpcServer::onGetBlockCount), true } },
      { "getblockhash", { makeMemberMethod(&RpcServer::onGetBlockHash), false } },
      { "getblocktemplate", { makeMemberMethod(&RpcServer::onGetBlockTemplate), false } },
      { "getblockheaderbyhash", { makeMemberMethod(&RpcServer::onGetBlockHeaderByHash), false } },
      { "getblockheaderbyheight", { makeMemberMethod(&RpcServer::onGetBlockHeaderByHeight), false } },
      { "getblocktimestamp", { makeMemberMethod(&RpcServer::onGetBlockTimestampByHeight), true } },
      { "getblockbyheight", { makeMemberMethod(&RpcServer::onGetBlockDetailsByHeight), false } },
      { "getblockbyhash", { makeMemberMethod(&RpcServer::onGetBlockDetailsByHash), false } },
      { "getblocksbyheights", { makeMemberMethod(&RpcServer::onGetBlocksDetailsByHeights), false } },
      { "getblocksbyhashes", { makeMemberMethod(&RpcServer::onGetBlocksDetailsByHashes), false } },
      { "getblockshashesbytimestamps", { makeMemberMethod(&RpcServer::onGetBlocksHashesByTimestamps), false } },
      { "getblockslist", { makeMemberMethod(&RpcServer::onGetBocksList), false } },
      { "getaltblockslist", { makeMemberMethod(&RpcServer::onGetAltBlocksList), true } },
      { "getlastblockheader", { makeMemberMethod(&RpcServer::onGetLastBlockHeader), false } },
      { "gettransaction", { makeMemberMethod(&RpcServer::onGetTransactionDetailsByHash), false } },
      { "gettransactionspool", { makeMemberMethod(&RpcServer::onGetTransactionsPool), false } },
      { "gettransactionsbypaymentid", { makeMemberMethod(&RpcServer::onGetTransactionsByPaymentId), false } },
      { "gettransactionhashesbypaymentid", { makeMemberMethod(&RpcServer::onGetTransactionHashesByPaymentId), false } },
      { "gettransactionsbyhashes", { makeMemberMethod(&RpcServer::onGetTransactionDetailsByHashes), false } },
      { "getcurrencyid", { makeMemberMethod(&RpcServer::onGetCurrencyId), true } },
      { "checktransactionkey", { makeMemberMethod(&RpcServer::onCheckTxSecretKey), false } },
      { "checktransactionbyviewkey", { makeMemberMethod(&RpcServer::onCheckTxWithViewKey), false } },
      { "checktransactionproof", { makeMemberMethod(&RpcServer::onCheckTxProof), false } },
      { "checkreserveproof", { makeMemberMethod(&RpcServer::onCheckReserveProof), false } },
      { "validateaddress", { makeMemberMethod(&RpcServer::onValidateAddress), false } },
      { "verifymessage", { makeMemberMethod(&RpcServer::onVerifyMessage), false } },
      { "submitblock", { makeMemberMethod(&RpcServer::onSubmitBlock), false } }

    };

    auto it = jsonRpcHandlers.find(jsonRequest.getMethod());
    if (it == jsonRpcHandlers.end()) {
      throw JsonRpcError(JsonRpc::errMethodNotFound);
    }

    if (!it->second.allowBusyCore && !isCoreReady()) {
      throw JsonRpcError(CORE_RPC_ERROR_CODE_CORE_BUSY, "Core is busy");
    }

    it->second.handler(this, jsonRequest, jsonResponse);

  } catch (const JsonRpcError& err) {
    jsonResponse.setError(err);
  } catch (const std::exception& e) {
    jsonResponse.setError(JsonRpcError(JsonRpc::errInternalError, e.what()));
  }

  response.setBody(jsonResponse.getBody());
  logger(TRACE) << "JSON-RPC response: " << jsonResponse.getBody();
  return true;
}

bool RpcServer::restrictRPC(const bool is_restricted) {
  m_restricted_rpc = is_restricted;
  return true;
}

bool RpcServer::enableCors(const std::vector<std::string> domains) {
  m_cors_domains = domains;
  return true;
}

std::vector<std::string> RpcServer::getCorsDomains() {
  return m_cors_domains;
}

bool RpcServer::setFeeAddress(const std::string& fee_address, const AccountPublicAddress& fee_acc) {
  m_fee_address = fee_address;
  m_fee_acc = fee_acc;
  return true;
}

bool RpcServer::setFeeAmount(const uint64_t fee_amount) {
  m_fee_amount = fee_amount;
  return true;
}

bool RpcServer::setViewKey(const std::string& view_key) {
  Crypto::Hash private_view_key_hash;
  size_t size;
  if (!Common::fromHex(view_key, &private_view_key_hash, sizeof(private_view_key_hash), size) || size != sizeof(private_view_key_hash)) {
    logger(INFO) << "Could not parse private view key";
    return false;
  }
  m_view_key = *(struct Crypto::SecretKey *) &private_view_key_hash;
  return true;
}

bool RpcServer::setContactInfo(const std::string& contact) {
  m_contact_info = contact;
  return true;
}

bool RpcServer::isCoreReady() {
  return m_core.getCurrency().isTestnet() || m_p2p.get_payload_object().isSynchronized();
}

bool RpcServer::checkIncomingTransactionForFee(const BinaryArray& tx_blob) {
  Crypto::Hash tx_hash = NULL_HASH;
  Crypto::Hash tx_prefixt_hash = NULL_HASH;
  Transaction tx;
  if (!parseAndValidateTransactionFromBinaryArray(tx_blob, tx, tx_hash, tx_prefixt_hash)) {
    logger(INFO) << "Could not parse tx from blob";
    return false;
  }
	
  // always relay fusion transactions
  uint64_t inputs_amount = 0;
  getInputsMoneyAmount(tx, inputs_amount);
  uint64_t outputs_amount = get_outs_money_amount(tx);

  const uint64_t fee = inputs_amount - outputs_amount;
  if (fee == 0 && m_core.getCurrency().isFusionTransaction(tx, tx_blob.size(), m_core.getTopBlockIndex())) {
    logger(DEBUGGING) << "Masternode received fusion transaction, relaying with no fee check";
    return true;
  }

  CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);

  std::vector<uint32_t> out;
  uint64_t amount;

  CryptoNote::findOutputsToAccount(transaction, m_fee_acc, m_view_key, out, amount);

  if (amount < m_fee_amount)
    return false;

  logger(Logging::INFO) << "Masternode received relayed transaction fee: " << m_core.getCurrency().formatAmount(amount) << " KRB";

  return true;
}

//
// Binary handlers
//

bool RpcServer::onGetBlocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res) {
  // TODO code duplication see InProcessNode::doGetNewBlocks()
  if (req.block_ids.empty()) {
    res.status = "Failed";
    return false;
  }

  if (req.block_ids.back() != m_core.getBlockHashByIndex(0)) {
    res.status = "Failed";
    return false;
  }

  uint32_t totalBlockCount;
  uint32_t startBlockIndex;
  std::vector<Crypto::Hash> supplement = m_core.findBlockchainSupplement(req.block_ids, COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT, totalBlockCount, startBlockIndex);

  res.current_height = totalBlockCount;
  res.start_height = startBlockIndex;

  std::vector<Crypto::Hash> missedHashes;
  m_core.getBlocks(supplement, res.blocks, missedHashes);
  assert(missedHashes.empty());

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onQueryBlocks(const COMMAND_RPC_QUERY_BLOCKS::request& req, COMMAND_RPC_QUERY_BLOCKS::response& res) {
  uint32_t startIndex;
  uint32_t currentIndex;
  uint32_t fullOffset;

  if (!m_core.queryBlocks(req.block_ids, req.timestamp, startIndex, currentIndex, fullOffset, res.items)) {
    res.status = "Failed to perform query";
    return false;
  }

  res.start_height = startIndex + 1;
  res.current_height = currentIndex + 1;
  res.full_offset = fullOffset;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onQueryBlocksLite(const COMMAND_RPC_QUERY_BLOCKS_LITE::request& req, COMMAND_RPC_QUERY_BLOCKS_LITE::response& res) {
  uint32_t startIndex;
  uint32_t currentIndex;
  uint32_t fullOffset;
  if (!m_core.queryBlocksLite(req.blockIds, req.timestamp, startIndex, currentIndex, fullOffset, res.items)) {
    res.status = "Failed to perform query";
    return false;
  }

  res.startHeight = startIndex;
  res.currentHeight = currentIndex;
  res.fullOffset = fullOffset;
  res.status = CORE_RPC_STATUS_OK;

  return true;
}

bool RpcServer::onGetIndexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res) {
  std::vector<uint32_t> outputIndexes;
  if (!m_core.getTransactionGlobalIndexes(req.txid, outputIndexes)) {
    res.status = "Failed";
    return true;
  }

  res.o_indexes.assign(outputIndexes.begin(), outputIndexes.end());
  res.status = CORE_RPC_STATUS_OK;
  logger(TRACE) << "COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES: [" << res.o_indexes.size() << "]";
  return true;
}

bool RpcServer::onGetRandomOuts(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res) {
  res.status = "Failed";

  for (uint64_t amount : req.amounts) {
    std::vector<uint32_t> globalIndexes;
    std::vector<Crypto::PublicKey> publicKeys;
    if (!m_core.getRandomOutputs(amount, static_cast<uint16_t>(req.outs_count), globalIndexes, publicKeys)) {
      return true;
    }

    assert(globalIndexes.size() == publicKeys.size());
    res.outs.emplace_back(COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_outs_for_amount{amount, {}});
    for (size_t i = 0; i < globalIndexes.size(); ++i) {
      res.outs.back().outs.push_back({globalIndexes[i], publicKeys[i]});
    }
  }

  res.status = CORE_RPC_STATUS_OK;

  std::stringstream ss;
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount outs_for_amount;
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry out_entry;

  std::for_each(res.outs.begin(), res.outs.end(), [&](outs_for_amount& ofa)  {
    ss << "[" << ofa.amount << "]:";

    assert(ofa.outs.size() && "internal error: ofa.outs.size() is empty");

    std::for_each(ofa.outs.begin(), ofa.outs.end(), [&](out_entry& oe)
    {
      ss << oe.global_amount_index << " ";
    });
    ss << ENDL;
  });
  std::string s = ss.str();
  logger(TRACE) << "COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS: " << ENDL << s;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetPoolChanges(const COMMAND_RPC_GET_POOL_CHANGES::request& req, COMMAND_RPC_GET_POOL_CHANGES::response& rsp) {
  rsp.status = CORE_RPC_STATUS_OK;
  rsp.isTailBlockActual = m_core.getPoolChanges(req.tailBlockId, req.knownTxsIds, rsp.addedTxs, rsp.deletedTxsIds);

  return true;
}

bool RpcServer::onGetPoolChangesLite(const COMMAND_RPC_GET_POOL_CHANGES_LITE::request& req, COMMAND_RPC_GET_POOL_CHANGES_LITE::response& rsp) {
  rsp.status = CORE_RPC_STATUS_OK;
  rsp.isTailBlockActual = m_core.getPoolChangesLite(req.tailBlockId, req.knownTxsIds, rsp.addedTxs, rsp.deletedTxsIds);

  return true;
}


//
// HTTP handlers
//

bool RpcServer::onGetIndex(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res) {
  const std::string index_start =
    R"(<html><head><meta http-equiv='refresh' content='60'/></head><body><p><svg xmlns="http://www.w3.org/2000/svg" xml:space="preserve" version="1.1" style="vertical-align:middle; padding-right: 10px; shape-rendering:geometricPrecision; text-rendering:geometricPrecision; image-rendering:optimizeQuality; fill-rule:evenodd; clip-rule:evenodd" viewBox="0 0 2500000 2500000" xmlns:xlink="http://www.w3.org/1999/xlink" width="64px" height="64px">
<g>
<circle fill="#0AACFC" cx="1250000" cy="1250000" r="1214062" />
<path fill="#FFED00" d="M1251219 1162750c18009,-3203 34019,-10006 48025,-20412 14009,-10407 27215,-28016 39622,-52029l275750 -538290c10803,-18010 24012,-32419 39218,-43625 15210,-10806 33219,-16410 53232,-16410l174893 0 -343384 633144c-15209,26016 -32419,47228 -51628,63635 -19613,16409 -41225,28815 -64838,37221 36822,9604 67638,25213 92854,47225 24812,21610 48425,52025 70437,91247l330578 668363 -192503 0c-38822,0 -70041,-21213 -93653,-63235l-270947 -566303c-14006,-25215 -29216,-43225 -45622,-54034 -16409,-10803 -37222,-17206 -62034,-18809l0 287359 -151281 0 0 -288559 -111263 0 0 703581 -213716 0 0 -1540835 213716 0 0 673166 111263 0 0 -332981 151281 0 0 330581z"/>
</g></svg></svg></td><td>)" "karbowanec" R"(d &bull; version 
)";
  const std::string index_finish = " </p></body></html>";
  const std::time_t uptime = std::time(nullptr) - m_core.getStartTime();
  const std::string uptime_str = std::to_string((unsigned int)floor(uptime / 60.0 / 60.0 / 24.0)) + "d " + std::to_string((unsigned int)floor(fmod((uptime / 60.0 / 60.0), 24.0))) + "h "
    + std::to_string((unsigned int)floor(fmod((uptime / 60.0), 60.0))) + "m " + std::to_string((unsigned int)fmod(uptime, 60.0)) + "s";
  uint32_t top_block_index = m_core.getCurrentBlockchainHeight() - 1;
  uint32_t top_known_block_index = std::max(static_cast<uint32_t>(1), m_protocol.getObservedHeight() - 1);
  size_t outConn = m_p2p.get_outgoing_connections_count();
  size_t incConn = m_p2p.get_connections_count() - outConn;
  Crypto::Hash last_block_hash = m_core.getTopBlockHash();
  size_t white_peerlist_size = m_p2p.getPeerlistManager().get_white_peers_count();
  size_t grey_peerlist_size = m_p2p.getPeerlistManager().get_gray_peers_count();
  size_t alt_blocks_count = m_core.getAlternativeBlocksCount();
  size_t total_tx_count = m_core.getBlockchainTransactionsCount() - top_block_index + 1;
  size_t tx_pool_count = m_core.getPoolTransactionsCount();

  const std::string body = index_start + PROJECT_VERSION_LONG + " &bull; " + (m_core.getCurrency().isTestnet() ? "testnet" : "mainnet") +
    "<ul>" +
    "<li>" + "Synchronization status: " + std::to_string(top_block_index) + "/" + std::to_string(top_known_block_index) +
    "<li>" + "Last block hash: " + Common::podToHex(last_block_hash) + "</li>" +
    "<li>" + "Difficulty: " + std::to_string(m_core.getDifficultyForNextBlock()) + "</li>" +
    "<li>" + "Alt. blocks: " + std::to_string(alt_blocks_count) + "</li>" +
    "<li>" + "Total transactions in network: " + std::to_string(total_tx_count) + "</li>" +
    "<li>" + "Transactions in pool: " + std::to_string(tx_pool_count) + "</li>" +
    "<li>" + "Connections:" +
    "<ul>" +
    "<li>" + "RPC: " + std::to_string(getConnectionsCount()) + "</li>" +
    "<li>" + "OUT: " + std::to_string(outConn) + "</li>" +
    "<li>" + "INC: " + std::to_string(incConn) + "</li>" +
    "</ul>" +
    "</li>" +
    "<li>" + "Peers: " + std::to_string(white_peerlist_size) + " white, " + std::to_string(grey_peerlist_size) + " grey" + "</li>" +
    "<li>" + "Uptime: " + uptime_str + "</li>" +
    "</ul>" +
    index_finish;

  res = body;

  return true;
}

bool RpcServer::onGetSupply(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res) {
  std::string already_generated_coins = m_core.getCurrency().formatAmount(m_core.getTotalGeneratedAmount());
  res = already_generated_coins;

  return true;
}

bool RpcServer::onGeneratePaymentId(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res) {
  Crypto::Hash result;
  Random::randomBytes(32, result.data);
  res = Common::podToHex(result);

  return true;
}

//
//  Binary handlers
//

bool RpcServer::onBinGetBlocksDetailsByHeights(const COMMAND_RPC_BIN_GET_BLOCKS_DETAILS_BY_HEIGHTS::request& req, COMMAND_RPC_BIN_GET_BLOCKS_DETAILS_BY_HEIGHTS::response& rsp) {
  try {
    std::vector<BlockDetails> blockDetails;
    for (const uint32_t& height : req.blockHeights) {
      blockDetails.push_back(m_core.getBlockDetails(height));
    }

    rsp.blocks = std::move(blockDetails);
  }
  catch (std::system_error & e) {
    rsp.status = e.what();
    return false;
  }
  catch (std::exception & e) {
    rsp.status = "Error: " + std::string(e.what());
    return false;
  }

  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onBinGetBlocksDetailsByHashes(const COMMAND_RPC_BIN_GET_BLOCKS_DETAILS_BY_HASHES::request& req, COMMAND_RPC_BIN_GET_BLOCKS_DETAILS_BY_HASHES::response& rsp) {
  try {
    std::vector<BlockDetails> blockDetails;
    for (const Crypto::Hash& hash : req.blockHashes) {
      blockDetails.push_back(m_core.getBlockDetails(hash));
    }

    rsp.blocks = std::move(blockDetails);
  }
  catch (std::system_error & e) {
    rsp.status = e.what();
    return false;
  }
  catch (std::exception & e) {
    rsp.status = "Error: " + std::string(e.what());
    return false;
  }

  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onBinGetBlocksHashesByTimestamps(const COMMAND_RPC_BIN_GET_BLOCKS_HASHES_BY_TIMESTAMPS::request& req, COMMAND_RPC_BIN_GET_BLOCKS_HASHES_BY_TIMESTAMPS::response& rsp) {
  try {
    auto blockHashes = m_core.getBlockHashesByTimestamps(req.timestampBegin, req.secondsCount);
    rsp.blockHashes = std::move(blockHashes);
  }
  catch (std::system_error & e) {
    rsp.status = e.what();
    return false;
  }
  catch (std::exception & e) {
    rsp.status = "Error: " + std::string(e.what());
    return false;
  }

  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onBinGetTransactionDetailsByHashes(const COMMAND_RPC_BIN_GET_TRANSACTION_DETAILS_BY_HASHES::request& req, COMMAND_RPC_BIN_GET_TRANSACTION_DETAILS_BY_HASHES::response& rsp) {
  try {
    std::vector<TransactionDetails> transactionDetails;
    transactionDetails.reserve(req.transactionHashes.size());

    for (const auto& hash : req.transactionHashes) {
      transactionDetails.push_back(m_core.getTransactionDetails(hash));
    }

    rsp.transactions = std::move(transactionDetails);
  }
  catch (std::system_error & e) {
    rsp.status = e.what();
    return false;
  }
  catch (std::exception & e) {
    rsp.status = "Error: " + std::string(e.what());
    return false;
  }

  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onBinGetTransactionHashesByPaymentId(const COMMAND_RPC_BIN_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::request& req, COMMAND_RPC_BIN_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::response& rsp) {
  try {
    rsp.transactionHashes = m_core.getTransactionHashesByPaymentId(req.paymentId);
  }
  catch (std::system_error & e) {
    rsp.status = e.what();
    return false;
  }
  catch (std::exception & e) {
    rsp.status = "Error: " + std::string(e.what());
    return false;
  }

  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

//
// JSON handlers
//

bool RpcServer::onGetBlocksDetailsByHeights(const COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS::request& req, COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS::response& rsp) {
  try {
    std::vector<BlockDetails> blockDetails;
    for (const uint32_t& height : req.blockHeights) {
      blockDetails.push_back(m_core.getBlockDetails(height));
    }

    rsp.blocks = std::move(blockDetails);
  } catch (std::system_error& e) {
    rsp.status = e.what();
    return false;
  } catch (std::exception& e) {
    rsp.status = "Error: " + std::string(e.what());
    return false;
  }

  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetBlocksDetailsByHashes(const COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES::request& req, COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES::response& rsp) {
  try {
    std::vector<BlockDetails> blockDetails;
    for (const Crypto::Hash& hash : req.blockHashes) {
      blockDetails.push_back(m_core.getBlockDetails(hash));
    }

    rsp.blocks = std::move(blockDetails);
  } catch (std::system_error& e) {
    rsp.status = e.what();
    return false;
  } catch (std::exception& e) {
    rsp.status = "Error: " + std::string(e.what());
    return false;
  }

  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetBlockDetailsByHeight(const COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::response& res) {
  if (m_core.getTopBlockIndex() < req.blockHeight) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("Invalid height: ") + std::to_string(req.blockHeight) + ", current blockchain height = " + std::to_string(m_core.getTopBlockIndex()) };
  }

  uint32_t index = static_cast<uint32_t>(req.blockHeight);
  auto block = m_core.getBlockByIndex(index);
  CachedBlock cachedBlock(block);
  assert(cachedBlock.getBlockIndex() == req.blockHeight);

  res.block = m_core.getBlockDetails(cachedBlock.getBlockHash());
  res.status = CORE_RPC_STATUS_OK;

  return true;
}

bool RpcServer::onGetBlockDetailsByHash(const COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::response& res) {
  BlockDetails blockDetails;
  Hash block_hash;
  if (!parse_hash256(req.hash, block_hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of block hash. Hex = " + req.hash + '.' };
  }
  res.block = m_core.getBlockDetails(block_hash);
  res.status = CORE_RPC_STATUS_OK;

  return true;
}

bool RpcServer::onGetBlocksHashesByTimestamps(const COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS::request& req, COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS::response& rsp) {
  try {
    auto blockHashes = m_core.getBlockHashesByTimestamps(req.timestampBegin, req.secondsCount);
    rsp.blockHashes = std::move(blockHashes);
  } catch (std::system_error& e) {
    rsp.status = e.what();
    return false;
  } catch (std::exception& e) {
    rsp.status = "Error: " + std::string(e.what());
    return false;
  }

  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetTransactionDetailsByHashes(const COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASHES::request& req, COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASHES::response& rsp) {
  try {
    std::vector<TransactionDetails> transactionDetails;
    transactionDetails.reserve(req.transactionHashes.size());

    for (const auto& hash: req.transactionHashes) {
      transactionDetails.push_back(m_core.getTransactionDetails(hash));
    }

    rsp.transactions = std::move(transactionDetails);
  } catch (std::system_error& e) {
    rsp.status = e.what();
    return false;
  } catch (std::exception& e) {
    rsp.status = "Error: " + std::string(e.what());
    return false;
  }

  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetTransactionDetailsByHash(const COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::request& req, COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::response& rsp) {
  Crypto::Hash tx_hash;
  if (!parse_hash256(req.hash, tx_hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of transaction hash. Hex = " + req.hash + '.' };
  }
  try {
    rsp.transaction = m_core.getTransactionDetails(tx_hash);
  }
  catch (std::system_error& e) {
    rsp.status = e.what();
    return false;
  }
  catch (std::exception& e) {
    rsp.status = "Error: " + std::string(e.what());
    return false;
  }

  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetTransactionHashesByPaymentId(const COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::request& req, COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::response& rsp) {
  Crypto::Hash pid_hash;
  if (!parse_hash256(req.paymentId, pid_hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of payment id. Hex = " + req.paymentId + '.' };
  }
  try {
    rsp.transactionHashes = m_core.getTransactionHashesByPaymentId(pid_hash);
  } catch (std::system_error& e) {
    rsp.status = e.what();
    return false;
  } catch (std::exception& e) {
    rsp.status = "Error: " + std::string(e.what());
    return false;
  }

  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetInfo(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res) {
  uint32_t topIndex = m_core.getTopBlockIndex();
  res.height = topIndex + 1;
  res.difficulty = m_core.getDifficultyForNextBlock();
  res.cumulative_difficulty = m_core.getBlockCumulativeDifficulty(topIndex);
  Crypto::Hash last_block_hash = m_core.getTopBlockHash();
  res.top_block_hash = Common::podToHex(last_block_hash);
  res.block_major_version = m_core.getBlockMajorVersionForHeight(m_core.getTopBlockIndex());
  res.transactions_count = m_core.getBlockchainTransactionsCount() - res.height; //without coinbase (incl. genesis)
  res.transactions_pool_size = m_core.getPoolTransactionsCount();
  res.alt_blocks_count = m_core.getAlternativeBlocksCount();
  uint64_t total_conn = m_p2p.get_connections_count();
  res.outgoing_connections_count = m_p2p.get_outgoing_connections_count();
  res.incoming_connections_count = total_conn - res.outgoing_connections_count;
  res.rpc_connections_count = getConnectionsCount();
  res.white_peerlist_size = m_p2p.getPeerlistManager().get_white_peers_count();
  res.grey_peerlist_size = m_p2p.getPeerlistManager().get_gray_peers_count();
  res.last_known_block_index = std::max(static_cast<uint32_t>(1), m_protocol.getObservedHeight() - 1);
  res.fee_address = m_fee_address.empty() ? std::string() : m_fee_address;
  res.contact = m_contact_info.empty() ? std::string() : m_contact_info;
  res.min_fee = m_core.getMinimalFee();
  uint64_t alreadyGeneratedCoins = m_core.getTotalGeneratedAmount();
  res.already_generated_coins = m_core.getCurrency().formatAmount(alreadyGeneratedCoins); // that large uint64_t number is unsafe in JavaScript environment and therefore as a JSON value so we display it as a formatted string
  res.next_reward = m_core.calculateReward(alreadyGeneratedCoins);
  res.start_time = (uint64_t)m_core.getStartTime();
  res.version = PROJECT_VERSION_LONG;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetHeight(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res) {
  res.height = m_core.getTopBlockIndex() + 1;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetTransactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res) {
  std::vector<Hash> vh;
  for (const auto& tx_hex_str : req.txs_hashes) {
    BinaryArray b;
    if (!fromHex(tx_hex_str, b)) {
      res.status = "Failed to parse hex representation of transaction hash";
      return true;
    }

    if (b.size() != sizeof(Hash)) {
      res.status = "Failed, size of data mismatch";
    }

    vh.push_back(*reinterpret_cast<const Hash*>(b.data()));
  }

  std::vector<Hash> missed_txs;
  std::vector<BinaryArray> txs;
  m_core.getTransactions(vh, txs, missed_txs);

  for (auto& tx : txs) {
    res.txs_as_hex.push_back(toHex(tx));
  }

  for (const auto& miss_tx : missed_txs) {
    res.missed_txs.push_back(Common::podToHex(miss_tx));
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onSendRawTx(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res) {
  std::vector<BinaryArray> transactions(1);
  if (!fromHex(req.tx_as_hex, transactions.back())) {
    logger(INFO) << "[on_send_raw_tx]: Failed to parse tx from hexbuff: " << req.tx_as_hex;
    res.status = "Failed";
    return true;
  }

  Crypto::Hash transactionHash = Crypto::cn_fast_hash(transactions.back().data(), transactions.back().size());
  logger(DEBUGGING) << "transaction " << transactionHash << " came in on_send_raw_tx";

  if (!m_fee_address.empty() && m_view_key != NULL_SECRET_KEY) {
    if (!checkIncomingTransactionForFee(transactions.back())) {
      logger(INFO) << "Transaction not relayed due to lack of masternode fee";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Not relayed due to lack of node fee" };
    }
  }

  if (!m_core.addTransactionToPool(transactions.back())) {
    logger(INFO) << "[on_send_raw_tx]: tx verification failed";
    res.status = "Failed";
    return true;
  }

  m_protocol.relayTransactions(transactions);

  res.status = CORE_RPC_STATUS_OK;
  return true;
}


bool RpcServer::onGetFeeAddress(const COMMAND_RPC_GET_FEE_ADDRESS::request& req, COMMAND_RPC_GET_FEE_ADDRESS::response& res) {
  res.status = CORE_RPC_STATUS_OK;

  if (m_fee_address.empty()) {
    return true;
  }

  res.fee_address = m_fee_address;
  res.fee_amount = m_fee_amount;
  return true;
}


bool RpcServer::onStopDaemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }
  if (m_core.getCurrency().isTestnet()) {
    m_p2p.sendStopSignal();
    res.status = CORE_RPC_STATUS_OK;
  } else {
    res.status = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
    return false;
  }

  return true;
}

bool RpcServer::onGetPeerList(const COMMAND_RPC_GET_PEER_LIST::request& req, COMMAND_RPC_GET_PEER_LIST::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  std::list<AnchorPeerlistEntry> pl_anchor;
  std::list<PeerlistEntry> pl_wite;
  std::list<PeerlistEntry> pl_gray;
  m_p2p.getPeerlistManager().get_peerlist_full(pl_anchor, pl_gray, pl_wite);
  for (const auto& pe : pl_anchor) {
    std::stringstream ss;
    ss << pe.adr;
    res.anchor_peers.push_back(ss.str());
  }
  for (const auto& pe : pl_wite) {
    std::stringstream ss;
    ss << pe.adr;
    res.white_peers.push_back(ss.str());
  }
  for (const auto& pe : pl_gray) {
    std::stringstream ss;
    ss << pe.adr;
    res.gray_peers.push_back(ss.str());
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetConnections(const COMMAND_RPC_GET_CONNECTIONS::request& req, COMMAND_RPC_GET_CONNECTIONS::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  std::vector<CryptoNoteConnectionContext> peers;
  if (!m_protocol.getConnections(peers)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get connections" };
  }

  for (const auto& p : peers) {
    p2p_connection_entry c;
    c.version = p.version;
    c.state = get_protocol_state_string(p.m_state);
    c.connection_id = boost::lexical_cast<std::string>(p.m_connection_id);
    c.remote_ip = Common::ipAddressToString(p.m_remote_ip);
    c.remote_port = p.m_remote_port;
    c.is_incoming = p.m_is_income;
    c.started = static_cast<uint64_t>(p.m_started);
    c.remote_blockchain_height = p.m_remote_blockchain_height;
    c.last_response_height = p.m_last_response_height;
    res.connections.push_back(c);
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

//------------------------------------------------------------------------------------------------------------------------------
// JSON RPC methods
//------------------------------------------------------------------------------------------------------------------------------

bool RpcServer::onGetBocksList(const COMMAND_RPC_GET_BLOCKS_LIST::request& req, COMMAND_RPC_GET_BLOCKS_LIST::response& res) {
  if (m_core.getTopBlockIndex() + 1 <= req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.getTopBlockIndex() + 1) };
  }

  uint32_t print_blocks_count = 10;
  if (req.count <= BLOCK_LIST_MAX_COUNT)
    print_blocks_count = req.count;

  uint32_t last_height = static_cast<uint32_t>(req.height - print_blocks_count);
  if (req.height <= print_blocks_count)  {
    last_height = 0;
  } 

  for (uint32_t i = static_cast<uint32_t>(req.height); i >= last_height; i--) {
    Hash block_hash = m_core.getBlockHashByIndex(static_cast<uint32_t>(i));
    if (!m_core.hasBlock(block_hash)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by height. Height = " + std::to_string(i) + '.' };
    }
    BlockDetailsShort b = m_core.getBlockDetailsLite(block_hash);

    block_short_response block_short;
    block_short.cumulative_size = b.blockSize;
    block_short.timestamp = b.timestamp;
    block_short.height = b.index;
    block_short.hash = Common::podToHex(b.hash);
    block_short.transactions_count = b.transactionsCount;
    block_short.difficulty = b.difficulty;
    block_short.min_fee = m_core.getMinimalFee(i);
    
    res.blocks.push_back(block_short);

    if (i == 0)
      break;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetAltBlocksList(const COMMAND_RPC_GET_ALT_BLOCKS_LIST::request& req, COMMAND_RPC_GET_ALT_BLOCKS_LIST::response& res) {
  std::vector<Crypto::Hash> altBlocksHashes = m_core.getAlternativeBlocksHashes();

  if (!altBlocksHashes.empty()) {
    for (const auto & h : altBlocksHashes) {
      
      BlockDetailsShort b = m_core.getBlockDetailsLite(h);

      block_short_response block_short;
      block_short.cumulative_size = b.blockSize;
      block_short.timestamp = b.timestamp;
      block_short.height = b.index;
      block_short.hash = Common::podToHex(b.hash);
      block_short.transactions_count = b.transactionsCount;
      block_short.difficulty = b.difficulty;
      block_short.min_fee = m_core.getMinimalFee(b.index);

      res.alt_blocks.push_back(block_short);
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetTransactionsPool(const COMMAND_RPC_GET_TRANSACTIONS_POOL::request& req, COMMAND_RPC_GET_TRANSACTIONS_POOL::response& res) {
  auto pool = m_core.getPoolTransactionsWithReceiveTime();
  for (const auto txrt : pool) {
	transaction_pool_response transaction_short;
	Transaction tx = txrt.first;
    uint64_t amount_in = getInputAmount(tx);
    uint64_t amount_out = getOutputAmount(tx);

    transaction_short.hash = Common::podToHex(getObjectHash(tx));
    transaction_short.fee = amount_in - amount_out;
    transaction_short.amount_out = amount_out;
    transaction_short.size = getObjectBinarySize(tx);
    transaction_short.receive_time = txrt.second;
    res.transactions.push_back(transaction_short);
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetTransactionsByPaymentId(const COMMAND_RPC_GET_TRANSACTIONS_BY_PAYMENT_ID::request& req, COMMAND_RPC_GET_TRANSACTIONS_BY_PAYMENT_ID::response& res) {
	if (!req.payment_id.size()) {
		throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong parameters, expected payment_id" };
	}

	Crypto::Hash paymentId;
	std::vector<Transaction> transactions;

	if (!parse_hash256(req.payment_id, paymentId)) {
		throw JsonRpc::JsonRpcError{
			CORE_RPC_ERROR_CODE_WRONG_PARAM,
			"Failed to parse Payment ID: " + req.payment_id + '.' };
	}

	if (!m_core.getTransactionsByPaymentId(paymentId, transactions)) {
		throw JsonRpc::JsonRpcError{
			CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
			"Internal error: can't get transactions by Payment ID: " + req.payment_id + '.' };
	}

	for (const Transaction& tx : transactions) {
		transaction_short_response transaction_short;
		uint64_t amount_in = getInputAmount(tx);
		uint64_t amount_out = getOutputAmount(tx);

		transaction_short.hash = Common::podToHex(getObjectHash(tx));
		transaction_short.fee = amount_in - amount_out;
		transaction_short.amount_out = amount_out;
		transaction_short.size = getObjectBinarySize(tx);
		res.transactions.push_back(transaction_short);
	}

	res.status = CORE_RPC_STATUS_OK;
	return true;
}

bool RpcServer::onGetBlockCount(const COMMAND_RPC_GETBLOCKCOUNT::request& req, COMMAND_RPC_GETBLOCKCOUNT::response& res) {
  res.count = m_core.getTopBlockIndex() + 1;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetBlockHash(const COMMAND_RPC_GETBLOCKHASH::request& req, COMMAND_RPC_GETBLOCKHASH::response& res) {
  if (req.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong parameters, expected height" };
  }

  uint32_t h = static_cast<uint32_t>(req[0]);
  Crypto::Hash blockId = m_core.getBlockHashByIndex(h);
  if (blockId == NULL_HASH) {
    throw JsonRpc::JsonRpcError{ 
      CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("Too big height: ") + std::to_string(h) + ", current blockchain height = " + std::to_string(m_core.getTopBlockIndex() + 1)
    };
  }

  res = Common::podToHex(blockId);
  return true;
}

namespace {
  uint64_t slow_memmem(void* start_buff, size_t buflen, void* pat, size_t patlen)
  {
    void* buf = start_buff;
    void* end = (char*)buf + buflen - patlen;
    while ((buf = memchr(buf, ((char*)pat)[0], buflen)))
    {
      if (buf>end)
        return 0;
      if (memcmp(buf, pat, patlen) == 0)
        return (char*)buf - (char*)start_buff;
      buf = (char*)buf + 1;
    }
    return 0;
  }
}

bool RpcServer::onGetBlockTemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& req, COMMAND_RPC_GETBLOCKTEMPLATE::response& res) {
  if (req.reserve_size > TX_EXTRA_NONCE_MAX_COUNT) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE, "To big reserved size, maximum 255" };
  }

  AccountPublicAddress acc = boost::value_initialized<AccountPublicAddress>();

  if (!req.wallet_address.size() || !m_core.getCurrency().parseAccountAddressString(req.wallet_address, acc)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_WALLET_ADDRESS, "Failed to parse wallet address" };
  }

  BlockTemplate blockTemplate = boost::value_initialized<BlockTemplate>();
  CryptoNote::BinaryArray blob_reserve;
  blob_reserve.resize(req.reserve_size, 0);

  if (!m_core.getBlockTemplate(blockTemplate, acc, blob_reserve, res.difficulty, res.height)) {
    logger(ERROR) << "Failed to create block template";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
  }

  BinaryArray block_blob = toBinaryArray(blockTemplate);
  PublicKey tx_pub_key = CryptoNote::getTransactionPublicKeyFromExtra(blockTemplate.baseTransaction.extra);
  if (tx_pub_key == NULL_PUBLIC_KEY) {
    logger(ERROR) << "Failed to find tx pub key in coinbase extra";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to find tx pub key in coinbase extra" };
  }

  if (0 < req.reserve_size) {
    res.reserved_offset = slow_memmem((void*)block_blob.data(), block_blob.size(), &tx_pub_key, sizeof(tx_pub_key));
    if (!res.reserved_offset) {
      logger(ERROR) << "Failed to find tx pub key in blockblob";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
    }
    res.reserved_offset += sizeof(tx_pub_key) + 3; //3 bytes: tag for TX_EXTRA_TAG_PUBKEY(1 byte), tag for TX_EXTRA_NONCE(1 byte), counter in TX_EXTRA_NONCE(1 byte)
    if (res.reserved_offset + req.reserve_size > block_blob.size()) {
      logger(ERROR) << "Failed to calculate offset for reserved bytes";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
    }
  } else {
    res.reserved_offset = 0;
  }

  res.blocktemplate_blob = toHex(block_blob);
  res.status = CORE_RPC_STATUS_OK;

  return true;
}

bool RpcServer::onGetCurrencyId(const COMMAND_RPC_GET_CURRENCY_ID::request& /*req*/, COMMAND_RPC_GET_CURRENCY_ID::response& res) {
  Hash genesisBlockHash = m_core.getCurrency().genesisBlockHash();
  res.currency_id_blob = Common::podToHex(genesisBlockHash);
  return true;
}

bool RpcServer::onSubmitBlock(const COMMAND_RPC_SUBMITBLOCK::request& req, COMMAND_RPC_SUBMITBLOCK::response& res) {
  if (req.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong param" };
  }

  BinaryArray blockblob;
  if (!fromHex(req[0], blockblob)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB, "Wrong block blob" };
  }

  auto blockToSend = blockblob;
  auto submitResult = m_core.submitBlock(std::move(blockblob));
  if (submitResult != error::AddBlockErrorCondition::BLOCK_ADDED) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_BLOCK_NOT_ACCEPTED, "Block not accepted" };
  }

  if (submitResult == error::AddBlockErrorCode::ADDED_TO_MAIN
      || submitResult == error::AddBlockErrorCode::ADDED_TO_ALTERNATIVE_AND_SWITCHED) {
    NOTIFY_NEW_BLOCK::request newBlockMessage;
    newBlockMessage.b = prepareRawBlockLegacy(std::move(blockToSend));
    newBlockMessage.hop = 0;
    newBlockMessage.current_blockchain_height = m_core.getTopBlockIndex() + 1; //+1 because previous version of core sent m_blocks.size()

    m_protocol.relayBlock(newBlockMessage);
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

RawBlockLegacy RpcServer::prepareRawBlockLegacy(BinaryArray&& blockBlob) {
  BlockTemplate blockTemplate;
  bool result = fromBinaryArray(blockTemplate, blockBlob);
  if (result) {}
  assert(result);

  RawBlockLegacy rawBlock;
  rawBlock.block = std::move(blockBlob);

  if (blockTemplate.transactionHashes.empty()) {
    return rawBlock;
  }

  rawBlock.transactions.reserve(blockTemplate.transactionHashes.size());
  std::vector<Crypto::Hash> missedTransactions;
  m_core.getTransactions(blockTemplate.transactionHashes, rawBlock.transactions, missedTransactions);
  assert(missedTransactions.empty());

  return rawBlock;
}

namespace {

uint64_t get_block_reward(const BlockTemplate& blk) {
  uint64_t reward = 0;
  for (const TransactionOutput& out : blk.baseTransaction.outputs) {
    reward += out.amount;
  }

  return reward;
}

}

void RpcServer::fillBlockHeaderResponse(const BlockTemplate& blk, bool orphan_status, uint32_t index, const Hash& hash, block_header_response& response) {
  response.major_version = blk.majorVersion;
  response.minor_version = blk.minorVersion;
  response.timestamp = blk.timestamp;
  response.prev_hash = Common::podToHex(blk.previousBlockHash);
  response.nonce = blk.nonce;
  response.orphan_status = orphan_status;
  response.height = index;
  response.depth = m_core.getTopBlockIndex() - index;
  response.hash = Common::podToHex(hash);
  response.difficulty = m_core.getBlockDifficulty(index);
  response.reward = get_block_reward(blk);
}

bool RpcServer::onGetLastBlockHeader(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res) {
  auto topBlock = m_core.getBlockByHash(m_core.getTopBlockHash());  
  fillBlockHeaderResponse(topBlock, false, m_core.getTopBlockIndex(), m_core.getTopBlockHash(), res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetBlockHeaderByHash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res) {
  Hash blockHash;
  if (!parse_hash256(req.hash, blockHash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of block hash. Hex = " + req.hash + '.' };
  }

  if (!m_core.hasBlock(blockHash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get block by hash. Hash = " + req.hash + '.' };
  }

  auto block = m_core.getBlockByHash(blockHash);
  CachedBlock cachedBlock(block);
  assert(block.baseTransaction.inputs.front().type() != typeid(BaseInput));

  fillBlockHeaderResponse(block, false, cachedBlock.getBlockIndex(), cachedBlock.getBlockHash(), res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetBlockHeaderByHeight(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res) {
  if (m_core.getTopBlockIndex() < req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.getTopBlockIndex()) };
  }

  uint32_t index = static_cast<uint32_t>(req.height);
  auto block = m_core.getBlockByIndex(index);
  CachedBlock cachedBlock(block);
  assert(cachedBlock.getBlockIndex() == req.height);
  fillBlockHeaderResponse(block, false, index, cachedBlock.getBlockHash(), res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetBlockTimestampByHeight(const COMMAND_RPC_GET_BLOCK_TIMESTAMP_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_TIMESTAMP_BY_HEIGHT::response& res) {
  if (m_core.getTopBlockIndex() < req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.getTopBlockIndex()) };
  }

  res.timestamp = m_core.getBlockTimestamp(req.height);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onCheckTxSecretKey(const COMMAND_RPC_CHECK_TX_KEY::request& req, COMMAND_RPC_CHECK_TX_KEY::response& res) {
  // parse txid
  Crypto::Hash txid;
  if (!parse_hash256(req.transaction_id, txid)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse txid" };
  }
  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.getCurrency().parseAccountAddressString(req.address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.address + '.' };
  }
  // parse txkey
  Crypto::Hash tx_key_hash;
  size_t size;
  if (!Common::fromHex(req.transaction_key, &tx_key_hash, sizeof(tx_key_hash), size) || size != sizeof(tx_key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse txkey" };
  }
  Crypto::SecretKey tx_key = *(struct Crypto::SecretKey *) &tx_key_hash;

  // fetch tx
  Transaction tx;
  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(txid);
  std::vector<Crypto::Hash> missed_txs;
  std::vector<BinaryArray> txs;
  m_core.getTransactions(tx_ids, txs, missed_txs);

  if (1 == txs.size()) {
    if (!fromBinaryArray(tx, txs.front())) {
      JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM, "Couldn't deserialize transaction" };
    }
  }
  else {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Couldn't find transaction with hash: " + req.transaction_id + '.' };
  }
  CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);

  // obtain key derivation
  Crypto::KeyDerivation derivation;
  if (!Crypto::generate_key_derivation(address.viewPublicKey, tx_key, derivation))
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to generate key derivation from supplied parameters" };
  }

  // look for outputs
  uint64_t received(0);
  size_t keyIndex(0);
  std::vector<TransactionOutput> outputs;
  try {
    for (const TransactionOutput& o : transaction.outputs) {
      if (o.target.type() == typeid(KeyOutput)) {
        const KeyOutput out_key = boost::get<KeyOutput>(o.target);
        Crypto::PublicKey pubkey;
        derive_public_key(derivation, keyIndex, address.spendPublicKey, pubkey);
        if (pubkey == out_key.key) {
          received += o.amount;
          outputs.push_back(o);
        }
      }
      ++keyIndex;
    }
  }
  catch (...)
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
  }
  res.amount = received;
  res.outputs = outputs;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onCheckTxWithViewKey(const COMMAND_RPC_CHECK_TX_WITH_PRIVATE_VIEW_KEY::request& req, COMMAND_RPC_CHECK_TX_WITH_PRIVATE_VIEW_KEY::response& res) {
  // parse txid
  Crypto::Hash txid;
  if (!parse_hash256(req.transaction_id, txid)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse txid" };
  }
  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.getCurrency().parseAccountAddressString(req.address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.address + '.' };
  }
  // parse view key
  Crypto::Hash view_key_hash;
  size_t size;
  if (!Common::fromHex(req.view_key, &view_key_hash, sizeof(view_key_hash), size) || size != sizeof(view_key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse private view key" };
  }
  Crypto::SecretKey viewKey = *(struct Crypto::SecretKey *) &view_key_hash;

  // fetch tx
  Transaction tx;
  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(txid);
  std::vector<Crypto::Hash> missed_txs;
  std::vector<BinaryArray> txs;
  m_core.getTransactions(tx_ids, txs, missed_txs);

  if (1 == txs.size()) {
    if (!fromBinaryArray(tx, txs.front())) {
      JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM, "Couldn't deserialize transaction" };
    }
  }
  else {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Couldn't find transaction with hash: " + req.transaction_id + '.' };
  }
  CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);

  // get tx pub key
  Crypto::PublicKey txPubKey = getTransactionPublicKeyFromExtra(transaction.extra);

  // obtain key derivation
  Crypto::KeyDerivation derivation;
  if (!Crypto::generate_key_derivation(txPubKey, viewKey, derivation))
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to generate key derivation from supplied parameters" };
  }

  // look for outputs
  uint64_t received(0);
  size_t keyIndex(0);
  std::vector<TransactionOutput> outputs;
  try {
    for (const TransactionOutput& o : transaction.outputs) {
      if (o.target.type() == typeid(KeyOutput)) {
        const KeyOutput out_key = boost::get<KeyOutput>(o.target);
        Crypto::PublicKey pubkey;
        derive_public_key(derivation, keyIndex, address.spendPublicKey, pubkey);
        if (pubkey == out_key.key) {
          received += o.amount;
          outputs.push_back(o);
        }
      }
      ++keyIndex;
    }
  }
  catch (...)
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
  }
  res.amount = received;
  res.outputs = outputs;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onCheckTxProof(const COMMAND_RPC_CHECK_TX_PROOF::request& req, COMMAND_RPC_CHECK_TX_PROOF::response& res) {
  // parse txid
  Crypto::Hash txid;
  if (!parse_hash256(req.transaction_id, txid)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse txid" };
  }
  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.getCurrency().parseAccountAddressString(req.destination_address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.destination_address + '.' };
  }
  // parse pubkey r*A & signature
  std::string decoded_data;
  uint64_t prefix;
  if (!Tools::Base58::decode_addr(req.signature, prefix, decoded_data) || prefix != CryptoNote::parameters::CRYPTONOTE_TX_PROOF_BASE58_PREFIX) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Transaction proof decoding error" };
  }
  Crypto::PublicKey rA;
  Crypto::Signature sig;
  
  std::string rA_decoded = decoded_data.substr(0, sizeof(Crypto::PublicKey));
  std::string sig_decoded = decoded_data.substr(sizeof(Crypto::PublicKey), sizeof(Crypto::Signature));

  memcpy(&rA, rA_decoded.data(), sizeof(Crypto::PublicKey));
  memcpy(&sig, sig_decoded.data(), sizeof(Crypto::Signature));

  // fetch tx pubkey
  Transaction tx;

  std::vector<uint32_t> out;
  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(txid);
  std::vector<Crypto::Hash> missed_txs;
  std::vector<BinaryArray> txs;
  m_core.getTransactions(tx_ids, txs, missed_txs);

  if (1 == txs.size()) {
    if (!fromBinaryArray(tx, txs.front())) {
      JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM, "Couldn't deserialize transaction" };
    }
  }
  else {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Couldn't find transaction with hash: " + req.transaction_id + '.' };
  }

  CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);

  Crypto::PublicKey R = getTransactionPublicKeyFromExtra(transaction.extra);
  if (R == NULL_PUBLIC_KEY)
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Tx pubkey was not found" };
  }

  // check signature
  bool r = Crypto::check_tx_proof(txid, R, address.viewPublicKey, rA, sig);
  res.signature_valid = r;

  if (r) {

    // obtain key derivation by multiplying scalar 1 to the pubkey r*A included in the signature
    Crypto::KeyDerivation derivation;
    if (!Crypto::generate_key_derivation(rA, Crypto::EllipticCurveScalar2SecretKey(Crypto::I), derivation)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to generate key derivation" };
    }

    // look for outputs
    uint64_t received(0);
    size_t keyIndex(0);
    std::vector<TransactionOutput> outputs;
    try {
      for (const TransactionOutput& o : transaction.outputs) {
        if (o.target.type() == typeid(KeyOutput)) {
          const KeyOutput out_key = boost::get<KeyOutput>(o.target);
          Crypto::PublicKey pubkey;
          derive_public_key(derivation, keyIndex, address.spendPublicKey, pubkey);
          if (pubkey == out_key.key) {
            received += o.amount;
            outputs.push_back(o);
          }
        }
        ++keyIndex;
      }
    }
    catch (...)
    {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
    }
    res.received_amount = received;
    res.outputs = outputs;

    TransactionDetails transactionDetails = m_core.getTransactionDetails(txid);
    res.confirmations = m_protocol.getObservedHeight() - transactionDetails.blockIndex;
  }
  else {
    res.received_amount = 0;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onCheckReserveProof(const COMMAND_RPC_CHECK_RESERVE_PROOF::request& req, COMMAND_RPC_CHECK_RESERVE_PROOF::response& res) {
  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.getCurrency().parseAccountAddressString(req.address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.address + '.' };
  }

  // parse sugnature
  std::string decoded_data;
  uint64_t prefix;
  if (!Tools::Base58::decode_addr(req.signature, prefix, decoded_data) || prefix != CryptoNote::parameters::CRYPTONOTE_RESERVE_PROOF_BASE58_PREFIX) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Reserve proof decoding error" };
  }
  BinaryArray ba(decoded_data.begin(), decoded_data.end());
  reserve_proof proof_decoded;
  if (!fromBinaryArray(proof_decoded, ba)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Reserve proof parsing error" };
  }

  std::vector<reserve_proof_entry>& proofs = proof_decoded.proofs;

  // compute signature prefix hash
  std::string prefix_data = req.message;
  prefix_data.append((const char*)&address, sizeof(CryptoNote::AccountPublicAddress));
  for (size_t i = 0; i < proofs.size(); ++i) {
    prefix_data.append((const char*)&proofs[i].key_image, sizeof(Crypto::PublicKey));
  }
  Crypto::Hash prefix_hash;
  Crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

  // fetch txes
  std::vector<Crypto::Hash> transactionHashes;
  for (size_t i = 0; i < proofs.size(); ++i) {
    transactionHashes.push_back(proofs[i].transaction_id);
  }
  std::vector<Hash> missed_txs;
  std::vector<BinaryArray> txs;
  m_core.getTransactions(transactionHashes, txs, missed_txs);
  std::vector<Transaction> transactions;

  // check spent status
  res.total = 0;
  res.spent = 0;
  for (size_t i = 0; i < proofs.size(); ++i) {
    const reserve_proof_entry& proof = proofs[i];
    Transaction tx;
    if (!fromBinaryArray(tx, txs[i])) {
      JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM, "Couldn't deserialize transaction" };
    }

    CryptoNote::TransactionPrefix txp = *static_cast<const TransactionPrefix*>(&tx);

    if (proof.index_in_transaction >= txp.outputs.size()) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "index_in_tx is out of bound" };
    }

    const KeyOutput out_key = boost::get<KeyOutput>(txp.outputs[proof.index_in_transaction].target);

    // get tx pub key
    Crypto::PublicKey txPubKey = getTransactionPublicKeyFromExtra(txp.extra);

    // check singature for shared secret
    if (!Crypto::check_tx_proof(prefix_hash, address.viewPublicKey, txPubKey, proof.shared_secret, proof.shared_secret_sig)) {
      //throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to check singature for shared secret" };
      res.good = false;
      return true;
    }

    // check signature for key image
    const std::vector<const Crypto::PublicKey *>& pubs = { &out_key.key };
    if (!Crypto::check_ring_signature(prefix_hash, proof.key_image, &pubs[0], 1, &proof.key_image_sig, false)) {
      //throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to check signature for key image" };
      res.good = false;
      return true;
    }

    // check if the address really received the fund
    Crypto::KeyDerivation derivation;
    if (!Crypto::generate_key_derivation(proof.shared_secret, Crypto::EllipticCurveScalar2SecretKey(Crypto::I), derivation)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to generate key derivation" };
    }
    try {
      Crypto::PublicKey pubkey;
      derive_public_key(derivation, proof.index_in_transaction, address.spendPublicKey, pubkey);
      if (pubkey == out_key.key) {
        uint64_t amount = txp.outputs[proof.index_in_transaction].amount;
        res.total += amount;

        if (req.height != 0) {
          if (m_core.isKeyImageSpent(proof.key_image, req.height)) {
            res.spent += amount;
          }
        }
        else {
          if (m_core.isKeyImageSpent(proof.key_image)) {
            res.spent += amount;
          }
        }
      }
    }
    catch (...)
    {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
    }

  }

  // check signature for address spend keys
  Crypto::Signature sig = proof_decoded.signature;
  if (!Crypto::check_signature(prefix_hash, address.spendPublicKey, sig)) {
    res.good = false;
    return true;
  }

  res.good = true;

  return true;
}

bool RpcServer::onValidateAddress(const COMMAND_RPC_VALIDATE_ADDRESS::request& req, COMMAND_RPC_VALIDATE_ADDRESS::response& res) {
  AccountPublicAddress acc = boost::value_initialized<AccountPublicAddress>();
  bool r = m_core.getCurrency().parseAccountAddressString(req.address, acc);
  res.is_valid = r;
  if (r) {
    res.address = m_core.getCurrency().accountAddressAsString(acc);
    res.spend_public_key = Common::podToHex(acc.spendPublicKey);
    res.view_public_key = Common::podToHex(acc.viewPublicKey);
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onVerifyMessage(const COMMAND_RPC_VERIFY_MESSAGE::request& req, COMMAND_RPC_VERIFY_MESSAGE::response& res) {
  AccountPublicAddress acc = boost::value_initialized<AccountPublicAddress>();
  if (!m_core.getCurrency().parseAccountAddressString(req.address, acc)) {
    throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_WRONG_PARAM, std::string("Failed to parse address"));
  }

  // could just've used this but detailed errors might be more handy
  //res.sig_valid = CryptoNote::verifyMessage(req.message, acc, req.signature, logger.getLogger());

  std::string decoded;
  Crypto::Signature s;
  uint64_t prefix;
  if (!Tools::Base58::decode_addr(req.signature, prefix, decoded) || prefix != CryptoNote::parameters::CRYPTONOTE_KEYS_SIGNATURE_BASE58_PREFIX) {
    throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_WRONG_PARAM, std::string("Signature decoding error"));
  }

  if (sizeof(s) != decoded.size()) {
    throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_WRONG_PARAM, std::string("Signature size wrong"));
    return false;
  }

  Crypto::Hash hash;
  Crypto::cn_fast_hash(req.message.data(), req.message.size(), hash);

  memcpy(&s, decoded.data(), sizeof(s));
  res.sig_valid = Crypto::check_signature(hash, acc.spendPublicKey, s);

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

}
