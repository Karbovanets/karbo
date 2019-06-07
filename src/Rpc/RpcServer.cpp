// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2016, The Forknote developers
// Copyright (c) 2016-2018, The Karbowanec developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#include "RpcServer.h"
#include "version.h"

#include <future>
#include <unordered_map>

// CryptoNote
#include "Common/StringTools.h"
#include "Common/Base58.h"
#include "CryptoNoteCore/TransactionUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteCore/TransactionUtils.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandlerCommon.h"
#include "CryptoNoteProtocol/ICryptoNoteProtocolQuery.h"

#include "P2p/NetNode.h"

#include "CoreRpcServerErrorCodes.h"
#include "JsonRpc.h"

#undef ERROR

using namespace Logging;
using namespace Crypto;
using namespace Common;

static const Crypto::SecretKey I = { { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

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
    response.setBody(storeToJson(res.data()));
    return result;
  };
}


}
  
std::unordered_map<std::string, RpcServer::RpcHandler<RpcServer::HandlerFunction>> RpcServer::s_handlers = {
  
  // binary handlers
  { "/getblocks.bin", { binMethod<COMMAND_RPC_GET_BLOCKS_FAST>(&RpcServer::on_get_blocks), false } },
  { "/queryblocks.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS>(&RpcServer::on_query_blocks), false } },
  { "/queryblockslite.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS_LITE>(&RpcServer::on_query_blocks_lite), false } },
  { "/get_o_indexes.bin", { binMethod<COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES>(&RpcServer::on_get_indexes), false } },
  { "/getrandom_outs.bin", { binMethod<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS>(&RpcServer::on_get_random_outs), false } },
  { "/get_pool_changes.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES>(&RpcServer::onGetPoolChanges), false } },
  { "/get_pool_changes_lite.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES_LITE>(&RpcServer::onGetPoolChangesLite), false } },

  // json handlers
  { "/getinfo", { jsonMethod<COMMAND_RPC_GET_INFO>(&RpcServer::on_get_info), true } },
  { "/getheight", { jsonMethod<COMMAND_RPC_GET_HEIGHT>(&RpcServer::on_get_height), true } },
  { "/gettransactions", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS>(&RpcServer::on_get_transactions), false } },
  { "/sendrawtransaction", { jsonMethod<COMMAND_RPC_SEND_RAW_TX>(&RpcServer::on_send_raw_tx), false } },

  { "/feeaddress", { jsonMethod<COMMAND_RPC_GET_FEE_ADDRESS>(&RpcServer::on_get_fee_address), true } },
  { "/peers", { jsonMethod<COMMAND_RPC_GET_PEER_LIST>(&RpcServer::on_get_peer_list), true } },
  { "/paymentid", { jsonMethod<COMMAND_RPC_GEN_PAYMENT_ID>(&RpcServer::on_get_payment_id), true } },
  
  // disabled in restricted rpc mode
  { "/stop_daemon", { jsonMethod<COMMAND_RPC_STOP_DAEMON>(&RpcServer::on_stop_daemon), true } },

  // These binary handlers were changed to JSON
  { "/get_block_details_by_height", { jsonMethod<COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT>(&RpcServer::onGetBlockDetailsByHeight), false } },
  { "/get_blocks_details_by_heights", { jsonMethod<COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS>(&RpcServer::onGetBlocksDetailsByHeights), false } },
  { "/get_blocks_details_by_hashes", { jsonMethod<COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES>(&RpcServer::onGetBlocksDetailsByHashes), false } },
  { "/get_blocks_hashes_by_timestamps", { jsonMethod<COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS>(&RpcServer::onGetBlocksHashesByTimestamps), false } },
  { "/get_transaction_details_by_hashes", { jsonMethod<COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASHES>(&RpcServer::onGetTransactionDetailsByHashes), false } },
  { "/get_transaction_hashes_by_payment_id", { jsonMethod<COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID>(&RpcServer::onGetTransactionHashesByPaymentId), false } },

  // json rpc
  { "/json_rpc", { std::bind(&RpcServer::processJsonRpcRequest, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), true } }
};

RpcServer::RpcServer(System::Dispatcher& dispatcher, Logging::ILogger& log, Core& c, NodeServer& p2p, ICryptoNoteProtocolHandler& protocol) :
  HttpServer(dispatcher, log), logger(log, "RpcServer"), m_core(c), m_p2p(p2p), m_protocol(protocol) {
}

void RpcServer::processRequest(const HttpRequest& request, HttpResponse& response) {
  auto url = request.getUrl();
  if (url.find(".bin") == std::string::npos) {
      logger(TRACE) << "RPC request came: \n" << request << std::endl;
  } else {
      logger(TRACE) << "RPC request came: " << url << std::endl;
  }

  auto it = s_handlers.find(url);
  if (it == s_handlers.end()) {
    response.setStatus(HttpResponse::STATUS_404);
    return;
  }

  if (!it->second.allowBusyCore && !isCoreReady()) {
    response.setStatus(HttpResponse::STATUS_500);
    response.setBody("Core is busy");
    return;
  }

  it->second.handler(this, request, response);
}

bool RpcServer::processJsonRpcRequest(const HttpRequest& request, HttpResponse& response) {

  using namespace JsonRpc;

  response.addHeader("Content-Type", "application/json");
  for (const auto& cors_domain: m_cors_domains) {
    response.addHeader("Access-Control-Allow-Origin", cors_domain);
  }

  JsonRpcRequest jsonRequest;
  JsonRpcResponse jsonResponse;

  try {
    logger(TRACE) << "JSON-RPC request: " << request.getBody();
    jsonRequest.parseRequest(request.getBody());
    jsonResponse.setId(jsonRequest.getId()); // copy id

    static std::unordered_map<std::string, RpcServer::RpcHandler<JsonMemberMethod>> jsonRpcHandlers = {
      { "getblockhash", { makeMemberMethod(&RpcServer::on_getblockhash), false } },
      { "getblocktemplate", { makeMemberMethod(&RpcServer::on_getblocktemplate), false } },
      { "getcurrencyid", { makeMemberMethod(&RpcServer::on_get_currency_id), true } },
      { "submitblock", { makeMemberMethod(&RpcServer::on_submitblock), false } },
      { "getlastblockheader", { makeMemberMethod(&RpcServer::on_get_last_block_header), false } },
      { "getblockheaderbyhash", { makeMemberMethod(&RpcServer::on_get_block_header_by_hash), false } },
      { "getblockheaderbyheight", { makeMemberMethod(&RpcServer::on_get_block_header_by_height), false } },
      { "getblockcount", { makeMemberMethod(&RpcServer::on_getblockcount), true } },
      { "f_blocks_list_json", { makeMemberMethod(&RpcServer::f_on_blocks_list_json), false } },
      { "f_block_json", { makeMemberMethod(&RpcServer::f_on_block_json), false } },
      { "f_transaction_json", { makeMemberMethod(&RpcServer::f_on_transaction_json), false } },
      { "f_transactions_pool", { makeMemberMethod(&RpcServer::f_on_transactions_pool_json), false } },
      { "f_mempool_json", { makeMemberMethod(&RpcServer::f_on_transactions_pool_json), false } },
      { "k_transactions_by_payment_id", { makeMemberMethod(&RpcServer::onTransactionsByPaymentId), false } },
      { "get_transaction_hashes_by_payment_id", { makeMemberMethod(&RpcServer::onGetTransactionHashesByPaymentId), false } },
      { "get_transaction_details_by_hashes", { makeMemberMethod(&RpcServer::onGetTransactionDetailsByHashes), false } },
      { "k_transaction_details_by_hash", { makeMemberMethod(&RpcServer::onGetTransactionDetailsByHash), false } },
      { "get_blocks_details_by_heights", { makeMemberMethod(&RpcServer::onGetBlocksDetailsByHeights), false } },
      { "get_block_details_by_height", { makeMemberMethod(&RpcServer::onGetBlockDetailsByHeight), false } },
      { "get_blocks_details_by_hashes", { makeMemberMethod(&RpcServer::onGetBlocksDetailsByHashes), false } },
      { "get_blocks_hashes_by_timestamps", { makeMemberMethod(&RpcServer::onGetBlocksHashesByTimestamps), false } },
      { "check_tx_key", { makeMemberMethod(&RpcServer::k_on_check_tx_key), false } },
      { "check_tx_with_view_key", { makeMemberMethod(&RpcServer::k_on_check_tx_with_view_key), false } },
      { "check_tx_proof", { makeMemberMethod(&RpcServer::k_on_check_tx_proof), false } },
      { "check_reserve_proof", { makeMemberMethod(&RpcServer::k_on_check_reserve_proof), false } },
      { "validateaddress", { makeMemberMethod(&RpcServer::on_validate_address), false } },
      { "verifymessage", { makeMemberMethod(&RpcServer::on_verify_message), false } }

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

bool RpcServer::setFeeAddress(const std::string& fee_address, const AccountPublicAddress& fee_acc) {
  m_fee_address = fee_address;
  m_fee_acc = fee_acc;
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

bool RpcServer::masternode_check_incoming_tx(const BinaryArray& tx_blob) {
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

  if (!CryptoNote::findOutputsToAccount(transaction, m_fee_acc, m_view_key, out, amount)) {
    logger(INFO) << "Could not find outputs to masternode fee address, not relaying transaction";
    return false;
  }

  if (amount != 0) {
    logger(INFO) << "Masternode received relayed transaction fee: " << m_core.getCurrency().formatAmount(amount) << " KRB";
    return true;
  }
  return false;
}

//
// Binary handlers
//

bool RpcServer::on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res) {
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

bool RpcServer::on_query_blocks(const COMMAND_RPC_QUERY_BLOCKS::request& req, COMMAND_RPC_QUERY_BLOCKS::response& res) {
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

bool RpcServer::on_query_blocks_lite(const COMMAND_RPC_QUERY_BLOCKS_LITE::request& req, COMMAND_RPC_QUERY_BLOCKS_LITE::response& res) {
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

bool RpcServer::on_get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res) {
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

bool RpcServer::on_get_random_outs(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res) {
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
  try {
    rsp.transaction = m_core.getTransactionDetails(req.hash);
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
  try {
    rsp.transactionHashes = m_core.getTransactionHashesByPaymentId(req.paymentId);
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

bool RpcServer::on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res) {
  res.height = m_core.getTopBlockIndex() + 1;
  res.difficulty = m_core.getDifficultyForNextBlock();
  res.tx_count = m_core.getBlockchainTransactionCount() - res.height; //without coinbase
  res.tx_pool_size = m_core.getPoolTransactionCount();
  res.alt_blocks_count = m_core.getAlternativeBlockCount();
  uint64_t total_conn = m_p2p.get_connections_count();
  res.outgoing_connections_count = m_p2p.get_outgoing_connections_count();
  res.incoming_connections_count = total_conn - res.outgoing_connections_count;
  res.rpc_connections_count = getConnectionsCount();
  res.white_peerlist_size = m_p2p.getPeerlistManager().get_white_peers_count();
  res.grey_peerlist_size = m_p2p.getPeerlistManager().get_gray_peers_count();
  res.last_known_block_index = std::max(static_cast<uint32_t>(1), m_protocol.getObservedHeight() - 1);
  Crypto::Hash last_block_hash = m_core.getTopBlockHash();
  res.top_block_hash = Common::podToHex(last_block_hash);
  res.version = PROJECT_VERSION_LONG;
  res.fee_address = m_fee_address.empty() ? std::string() : m_fee_address;
  res.contact = m_contact_info.empty() ? std::string() : m_contact_info;
  res.min_tx_fee = m_core.getMinimalFee();
  res.readable_tx_fee = m_core.getCurrency().formatAmount(res.min_tx_fee);
  res.start_time = (uint64_t)m_core.getStartTime();
  res.already_generated_coins = m_core.getCurrency().formatAmount(m_core.getTotalGeneratedAmount()); // that large uint64_t number is unsafe in JavaScript environment and therefore as a JSON value so we display it as a formatted string
  res.block_major_version = m_core.getBlockMajorVersionForHeight(m_core.getTopBlockIndex());

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_height(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res) {
  res.height = m_core.getTopBlockIndex() + 1;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res) {
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
    res.missed_tx.push_back(Common::podToHex(miss_tx));
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_send_raw_tx(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res) {
  std::vector<BinaryArray> transactions(1);
  if (!fromHex(req.tx_as_hex, transactions.back())) {
    logger(INFO) << "[on_send_raw_tx]: Failed to parse tx from hexbuff: " << req.tx_as_hex;
    res.status = "Failed";
    return true;
  }

  Crypto::Hash transactionHash = Crypto::cn_fast_hash(transactions.back().data(), transactions.back().size());
  logger(DEBUGGING) << "transaction " << transactionHash << " came in on_send_raw_tx";

  if (!m_fee_address.empty() && m_view_key != NULL_SECRET_KEY) {
    if (!masternode_check_incoming_tx(transactions.back())) {
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

  //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
  res.status = CORE_RPC_STATUS_OK;
  return true;
}


bool RpcServer::on_get_fee_address(const COMMAND_RPC_GET_FEE_ADDRESS::request& req, COMMAND_RPC_GET_FEE_ADDRESS::response& res) {
  if (m_fee_address.empty()) {
    res.status = "Node's fee address is not set";
    return false;
  }

  res.fee_address = m_fee_address;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}


bool RpcServer::on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res) {
  if (m_restricted_rpc) {
    res.status = "Failed, restricted handle";
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

bool RpcServer::on_get_peer_list(const COMMAND_RPC_GET_PEER_LIST::request& req, COMMAND_RPC_GET_PEER_LIST::response& res) {
	std::list<PeerlistEntry> pl_wite;
	std::list<PeerlistEntry> pl_gray;
	m_p2p.getPeerlistManager().get_peerlist_full(pl_gray, pl_wite);
	for (const auto& pe : pl_wite) {
		std::stringstream ss;
		ss << pe.adr;
		res.peers.push_back(ss.str());
	}
	res.status = CORE_RPC_STATUS_OK;
	return true;
}

bool RpcServer::on_get_payment_id(const COMMAND_RPC_GEN_PAYMENT_ID::request& req, COMMAND_RPC_GEN_PAYMENT_ID::response& res) {
  res = Common::podToHex(Crypto::rand<Crypto::Hash>());
  return true;
}

//------------------------------------------------------------------------------------------------------------------------------
// JSON RPC methods
//------------------------------------------------------------------------------------------------------------------------------

bool RpcServer::f_on_blocks_list_json(const F_COMMAND_RPC_GET_BLOCKS_LIST::request& req, F_COMMAND_RPC_GET_BLOCKS_LIST::response& res) {
  if (m_core.getTopBlockIndex() + 1 <= req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.getTopBlockIndex() + 1) };
  }

  uint32_t print_blocks_count = 30;
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
    BlockTemplate blk = m_core.getBlockByHash(block_hash);
    BlockDetails blkDetails = m_core.getBlockDetails(block_hash);

    f_block_short_response block_short;
    block_short.cumul_size = blkDetails.blockSize;
    block_short.timestamp = blk.timestamp;
    block_short.height = i;
    block_short.hash = Common::podToHex(block_hash);
    block_short.tx_count = blk.transactionHashes.size() + 1;
    block_short.difficulty = m_core.getBlockDifficulty(static_cast<uint32_t>(i));
    block_short.min_tx_fee = m_core.getMinimalFeeForHeight(i);

    res.blocks.push_back(block_short);

    if (i == 0)
      break;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::f_on_block_json(const F_COMMAND_RPC_GET_BLOCK_DETAILS::request& req, F_COMMAND_RPC_GET_BLOCK_DETAILS::response& res) {
  Hash hash;

  try {
    uint32_t height = boost::lexical_cast<uint32_t>(req.hash);
    hash = m_core.getBlockHashByIndex(height);
  } catch (boost::bad_lexical_cast &) {
    if (!parse_hash256(req.hash, hash)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "Failed to parse hex representation of block hash. Hex = " + req.hash + '.' };
    }
  }

  if (!m_core.hasBlock(hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get block by hash. Hash = " + req.hash + '.' };
  }
  BlockTemplate blk = m_core.getBlockByHash(hash);
  BlockDetails blkDetails = m_core.getBlockDetails(hash);

  if (blk.baseTransaction.inputs.front().type() != typeid(BaseInput)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: coinbase transaction in the block has the wrong type" };
  }

  block_header_response block_header;
  res.block.height = boost::get<BaseInput>(blk.baseTransaction.inputs.front()).blockIndex;
  fill_block_header_response(blk, false, res.block.height, hash, block_header);

  res.block.major_version = block_header.major_version;
  res.block.minor_version = block_header.minor_version;
  res.block.timestamp = block_header.timestamp;
  res.block.prev_hash = block_header.prev_hash;
  res.block.nonce = block_header.nonce;
  res.block.hash = Common::podToHex(hash);
  res.block.depth = m_core.getTopBlockIndex() - res.block.height;
  res.block.difficulty = m_core.getBlockDifficulty(res.block.height);
  res.block.transactionsCumulativeSize = blkDetails.transactionsCumulativeSize;
  res.block.alreadyGeneratedCoins = std::to_string(blkDetails.alreadyGeneratedCoins);
  res.block.alreadyGeneratedTransactions = blkDetails.alreadyGeneratedTransactions;
  res.block.reward = block_header.reward;
  res.block.sizeMedian = blkDetails.sizeMedian;
  res.block.blockSize = blkDetails.blockSize;
  res.block.orphan_status = blkDetails.isAlternative;

  size_t blockGrantedFullRewardZone = m_core.getCurrency().blockGrantedFullRewardZoneByBlockVersion(block_header.major_version);
  res.block.effectiveSizeMedian = std::max(res.block.sizeMedian, blockGrantedFullRewardZone);

  res.block.baseReward = blkDetails.baseReward;
  res.block.penalty = blkDetails.penalty;

  // Base transaction adding
  f_transaction_short_response transaction_short;
  transaction_short.hash = Common::podToHex(getObjectHash(blk.baseTransaction));
  transaction_short.fee = 0;
  transaction_short.amount_out = getOutputAmount(blk.baseTransaction);
  transaction_short.size = getObjectBinarySize(blk.baseTransaction);
  res.block.transactions.push_back(transaction_short);

  std::vector<Crypto::Hash> missed_txs;
  std::vector<BinaryArray> txs;
  m_core.getTransactions(blk.transactionHashes, txs, missed_txs);

  res.block.totalFeeAmount = 0;

  for (const BinaryArray& ba : txs) {
    Transaction tx;
    if (!fromBinaryArray(tx, ba)) {
      throw std::runtime_error("Couldn't deserialize transaction");
    }
    f_transaction_short_response transaction_short;
    uint64_t amount_in = getInputAmount(tx);
    uint64_t amount_out = getOutputAmount(tx);

    transaction_short.hash = Common::podToHex(getObjectHash(tx));
    transaction_short.fee = amount_in - amount_out;
    transaction_short.amount_out = amount_out;
    transaction_short.size = getObjectBinarySize(tx);
    res.block.transactions.push_back(transaction_short);

    res.block.totalFeeAmount += transaction_short.fee;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::f_on_transaction_json(const F_COMMAND_RPC_GET_TRANSACTION_DETAILS::request& req, F_COMMAND_RPC_GET_TRANSACTION_DETAILS::response& res) {
  Hash hash;

  if (!parse_hash256(req.hash, hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of transaction hash. Hex = " + req.hash + '.' };
  }

  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(hash);

  std::vector<Crypto::Hash> missed_txs;
  std::vector<BinaryArray> txs;
  m_core.getTransactions(tx_ids, txs, missed_txs);

  if (1 == txs.size()) {
    Transaction transaction;
    if (!fromBinaryArray(transaction, txs.front())) {
      throw std::runtime_error("Couldn't deserialize transaction");
    }
    res.tx = transaction;
  } else {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "transaction wasn't found. Hash = " + req.hash + '.' };
  }
  TransactionDetails transactionDetails = m_core.getTransactionDetails(hash);

  Crypto::Hash blockHash;
  if (transactionDetails.inBlockchain) {
    uint32_t blockHeight = transactionDetails.blockIndex;
    if (!blockHeight) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get transaction by hash. Hash = " + Common::podToHex(hash) + '.' };
    }
    res.txDetails.confirmations = m_protocol.getObservedHeight() - blockHeight;
    blockHash = m_core.getBlockHashByIndex(blockHeight);
    BlockTemplate blk = m_core.getBlockByHash(blockHash);
    BlockDetails blkDetails = m_core.getBlockDetails(blockHash);

    f_block_short_response block_short;

    block_short.cumul_size = blkDetails.blockSize;
    block_short.timestamp = blk.timestamp;
    block_short.height = blockHeight;
    block_short.hash = Common::podToHex(blockHash);
    block_short.tx_count = blk.transactionHashes.size() + 1;
    res.block = block_short;
  }

  uint64_t amount_in = getInputAmount(res.tx);
  uint64_t amount_out = getOutputAmount(res.tx);

  res.txDetails.hash = Common::podToHex(getObjectHash(res.tx));
  res.txDetails.fee = amount_in - amount_out;
  if (amount_in == 0)
    res.txDetails.fee = 0;
  res.txDetails.amount_out = amount_out;
  res.txDetails.size = getObjectBinarySize(res.tx);

  uint64_t mixin;
  if (!m_core.getMixin(res.tx, mixin)) {
    return false;
  }
  res.txDetails.mixin = mixin;

  Crypto::Hash paymentId;
  if (CryptoNote::getPaymentIdFromTxExtra(res.tx.extra, paymentId)) {
    res.txDetails.paymentId = Common::podToHex(paymentId);
  } else {
    res.txDetails.paymentId = "";
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::f_on_transactions_pool_json(const COMMAND_RPC_GET_MEMPOOL::request& req, COMMAND_RPC_GET_MEMPOOL::response& res) {
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
    transaction_short.receiveTime = txrt.second;
    res.transactions.push_back(transaction_short);
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onTransactionsByPaymentId(const K_COMMAND_RPC_GET_TRANSACTIONS_BY_PAYMENT_ID::request& req, K_COMMAND_RPC_GET_TRANSACTIONS_BY_PAYMENT_ID::response& res) {
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
		f_transaction_short_response transaction_short;
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

bool RpcServer::on_getblockcount(const COMMAND_RPC_GETBLOCKCOUNT::request& req, COMMAND_RPC_GETBLOCKCOUNT::response& res) {
  res.count = m_core.getTopBlockIndex() + 1;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_getblockhash(const COMMAND_RPC_GETBLOCKHASH::request& req, COMMAND_RPC_GETBLOCKHASH::response& res) {
  //if (req.size() != 1) {
  //  throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong parameters, expected height" };
  //}

  //uint32_t h = static_cast<uint32_t>(req[0]);
  uint32_t h = static_cast<uint32_t>(req.height);
  Crypto::Hash blockId = m_core.getBlockHashByIndex(h);
  if (blockId == NULL_HASH) {
    throw JsonRpc::JsonRpcError{ 
      CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("Too big height: ") + std::to_string(h) + ", current blockchain height = " + std::to_string(m_core.getTopBlockIndex() + 1)
    };
  }

  res.block_hash = Common::podToHex(blockId);
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

bool RpcServer::on_getblocktemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& req, COMMAND_RPC_GETBLOCKTEMPLATE::response& res) {
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

bool RpcServer::on_get_currency_id(const COMMAND_RPC_GET_CURRENCY_ID::request& /*req*/, COMMAND_RPC_GET_CURRENCY_ID::response& res) {
  Hash genesisBlockHash = m_core.getCurrency().genesisBlockHash();
  res.currency_id_blob = Common::podToHex(genesisBlockHash);
  return true;
}

bool RpcServer::on_submitblock(const COMMAND_RPC_SUBMITBLOCK::request& req, COMMAND_RPC_SUBMITBLOCK::response& res) {
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

void RpcServer::fill_block_header_response(const BlockTemplate& blk, bool orphan_status, uint32_t index, const Hash& hash, block_header_response& response) {
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

bool RpcServer::on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res) {
  auto topBlock = m_core.getBlockByHash(m_core.getTopBlockHash());  
  fill_block_header_response(topBlock, false, m_core.getTopBlockIndex(), m_core.getTopBlockHash(), res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res) {
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

  fill_block_header_response(block, false, cachedBlock.getBlockIndex(), cachedBlock.getBlockHash(), res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res) {
  if (m_core.getTopBlockIndex() < req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.getTopBlockIndex()) };
  }

  uint32_t index = static_cast<uint32_t>(req.height);
  auto block = m_core.getBlockByIndex(index);
  CachedBlock cachedBlock(block);
  assert(cachedBlock.getBlockIndex() == req.height);
  fill_block_header_response(block, false, index, cachedBlock.getBlockHash(), res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::k_on_check_tx_key(const K_COMMAND_RPC_CHECK_TX_KEY::request& req, K_COMMAND_RPC_CHECK_TX_KEY::response& res) {
  // parse txid
  Crypto::Hash txid;
  if (!parse_hash256(req.txid, txid)) {
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
  if (!Common::fromHex(req.txkey, &tx_key_hash, sizeof(tx_key_hash), size) || size != sizeof(tx_key_hash)) {
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
      "Couldn't find transaction with hash: " + req.txid + '.' };
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

bool RpcServer::k_on_check_tx_with_view_key(const K_COMMAND_RPC_CHECK_TX_WITH_PRIVATE_VIEW_KEY::request& req, K_COMMAND_RPC_CHECK_TX_WITH_PRIVATE_VIEW_KEY::response& res) {
  // parse txid
  Crypto::Hash txid;
  if (!parse_hash256(req.txid, txid)) {
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
      "Couldn't find transaction with hash: " + req.txid + '.' };
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

bool RpcServer::k_on_check_tx_proof(const K_COMMAND_RPC_CHECK_TX_PROOF::request& req, K_COMMAND_RPC_CHECK_TX_PROOF::response& res) {
  // parse txid
  Crypto::Hash txid;
  if (!parse_hash256(req.tx_id, txid)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse txid" };
  }
  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.getCurrency().parseAccountAddressString(req.dest_address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.dest_address + '.' };
  }
  // parse pubkey r*A & signature
  const size_t header_len = strlen("ProofV1");
  if (req.signature.size() < header_len || req.signature.substr(0, header_len) != "ProofV1") {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Signature header check error" };
  }
  Crypto::PublicKey rA;
  Crypto::Signature sig;
  const size_t rA_len = Tools::Base58::encode(std::string((const char *)&rA, sizeof(Crypto::PublicKey))).size();
  const size_t sig_len = Tools::Base58::encode(std::string((const char *)&sig, sizeof(Crypto::Signature))).size();
  std::string rA_decoded;
  std::string sig_decoded;
  if (!Tools::Base58::decode(req.signature.substr(header_len, rA_len), rA_decoded)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Signature decoding error" };
  }
  if (!Tools::Base58::decode(req.signature.substr(header_len + rA_len, sig_len), sig_decoded)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Signature decoding error" };
  }
  if (sizeof(Crypto::PublicKey) != rA_decoded.size() || sizeof(Crypto::Signature) != sig_decoded.size()) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Signature decoding error" };
  }
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
      "Couldn't find transaction with hash: " + req.tx_id + '.' };
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
    if (!Crypto::generate_key_derivation(rA, I, derivation)) {
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

bool RpcServer::k_on_check_reserve_proof(const K_COMMAND_RPC_CHECK_RESERVE_PROOF::request& req, K_COMMAND_RPC_CHECK_RESERVE_PROOF::response& res) {
  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.getCurrency().parseAccountAddressString(req.address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.address + '.' };
  }

  // parse sugnature
  static constexpr char header[] = "ReserveProofV1";
  const size_t header_len = strlen(header);
  if (req.signature.size() < header_len || req.signature.substr(0, header_len) != header) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Signature header check error" };
  }

  std::string sig_decoded;
  if (!Tools::Base58::decode(req.signature.substr(header_len), sig_decoded)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Signature decoding error" };
  }

  BinaryArray ba;
  if (!Common::fromHex(sig_decoded, ba)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Proof decoding error" };
  }
  reserve_proof proof_decoded;
  if (!fromBinaryArray(proof_decoded, ba)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "BinaryArray decoding error" };
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
    transactionHashes.push_back(proofs[i].txid);
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

    if (proof.index_in_tx >= txp.outputs.size()) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "index_in_tx is out of bound" };
    }

    const KeyOutput out_key = boost::get<KeyOutput>(txp.outputs[proof.index_in_tx].target);

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
    if (!Crypto::generate_key_derivation(proof.shared_secret, I, derivation)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to generate key derivation" };
    }
    try {
      Crypto::PublicKey pubkey;
      derive_public_key(derivation, proof.index_in_tx, address.spendPublicKey, pubkey);
      if (pubkey == out_key.key) {
        uint64_t amount = txp.outputs[proof.index_in_tx].amount;
        res.total += amount;

        if (m_core.isKeyImageSpent(proof.key_image)) {
          res.spent += amount;
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

bool RpcServer::on_validate_address(const COMMAND_RPC_VALIDATE_ADDRESS::request& req, COMMAND_RPC_VALIDATE_ADDRESS::response& res) {
  AccountPublicAddress acc = boost::value_initialized<AccountPublicAddress>();
  bool r = m_core.getCurrency().parseAccountAddressString(req.address, acc);
  res.isvalid = r;
  if (r) {
    res.address = m_core.getCurrency().accountAddressAsString(acc);
    res.spendPublicKey = Common::podToHex(acc.spendPublicKey);
    res.viewPublicKey = Common::podToHex(acc.viewPublicKey);
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_verify_message(const COMMAND_RPC_VERIFY_MESSAGE::request& req, COMMAND_RPC_VERIFY_MESSAGE::response& res) {
  Crypto::Hash hash;
  Crypto::cn_fast_hash(req.message.data(), req.message.size(), hash);

  AccountPublicAddress acc = boost::value_initialized<AccountPublicAddress>();
  if (!m_core.getCurrency().parseAccountAddressString(req.address, acc)) {
    throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_WRONG_PARAM, std::string("Failed to parse address"));
  }

  const size_t header_len = strlen("SigV1");
  if (req.signature.size() < header_len || req.signature.substr(0, header_len) != "SigV1") {
    throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_WRONG_PARAM, std::string("Signature header check error"));
  }
  std::string decoded;
  Crypto::Signature s;
  if (!Tools::Base58::decode(req.signature.substr(header_len), decoded) || sizeof(s) != decoded.size()) {
    throw JsonRpc::JsonRpcError(CORE_RPC_ERROR_CODE_WRONG_PARAM, std::string("Signature decoding error"));
    return false;
  }
  memcpy(&s, decoded.data(), sizeof(s));
  res.sig_valid = Crypto::check_signature(hash, acc.spendPublicKey, s);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

}
