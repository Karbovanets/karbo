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

#pragma once

#include <vector>
#include <boost/variant.hpp>

#include "android.h"
#include "json.hpp"
#include "CryptoTypes.h"
#include <Common/StringTools.h>

namespace CryptoNote {

struct BaseInput {
  uint32_t blockIndex;
};

struct KeyInput {
  uint64_t amount;
  std::vector<uint32_t> outputIndexes;
  Crypto::KeyImage keyImage;
};

struct MultisignatureInput {
  uint64_t amount;
  uint8_t signatureCount;
  uint32_t outputIndex;
};

struct KeyOutput {
  Crypto::PublicKey key;
};

struct MultisignatureOutput {
  std::vector<Crypto::PublicKey> keys;
  uint8_t requiredSignatureCount;
};

typedef boost::variant<BaseInput, KeyInput, MultisignatureInput> TransactionInput;

typedef boost::variant<KeyOutput, MultisignatureOutput> TransactionOutputTarget;

struct TransactionOutput {
  uint64_t amount;
  TransactionOutputTarget target;
};

struct TransactionPrefix {
  uint8_t version;
  uint64_t unlockTime;
  std::vector<TransactionInput> inputs;
  std::vector<TransactionOutput> outputs;
  std::vector<uint8_t> extra;
};

struct Transaction : public TransactionPrefix {
  std::vector<std::vector<Crypto::Signature>> signatures;
};

struct BaseTransaction : public TransactionPrefix {
};

struct ParentBlock {
  uint8_t majorVersion;
  uint8_t minorVersion;
  Crypto::Hash previousBlockHash;
  uint16_t transactionCount;
  std::vector<Crypto::Hash> baseTransactionBranch;
  BaseTransaction baseTransaction;
  std::vector<Crypto::Hash> blockchainBranch;
};

struct BlockHeader {
  uint8_t majorVersion;
  uint8_t minorVersion;
  uint32_t nonce;
  uint64_t timestamp;
  Crypto::Hash previousBlockHash;
};

struct BlockTemplate : public BlockHeader {
  ParentBlock parentBlock;
  Transaction baseTransaction;
  std::vector<Crypto::Hash> transactionHashes;
};

struct AccountPublicAddress {
  Crypto::PublicKey spendPublicKey;
  Crypto::PublicKey viewPublicKey;
};

struct AccountKeys {
  AccountPublicAddress address;
  Crypto::SecretKey spendSecretKey;
  Crypto::SecretKey viewSecretKey;
};

struct KeyPair {
  Crypto::PublicKey publicKey;
  Crypto::SecretKey secretKey;
};

using BinaryArray = std::vector<uint8_t>;

struct RawBlock {
  BinaryArray block; //BlockTemplate
  std::vector<BinaryArray> transactions;
};

inline void to_json(nlohmann::json &j, const CryptoNote::KeyInput &k)
{
    j = {
        {"amount", k.amount},
        {"key_offsets", k.outputIndexes},
        {"k_image", k.keyImage}
    };
}

inline void from_json(const nlohmann::json &j, CryptoNote::KeyInput &k)
{
    k.amount = j.at("amount").get<uint64_t>();
    k.outputIndexes = j.at("key_offsets").get<std::vector<uint32_t>>();
    k.keyImage = j.at("k_image").get<Crypto::KeyImage>();
}

inline void to_json(nlohmann::json &j, const CryptoNote::RawBlock &block)
{
    std::vector<std::string> transactions;

    for (auto transaction : block.transactions)
    {
        transactions.push_back(Common::toHex(transaction));
    }

    j = {
        {"block", Common::toHex(block.block)},
        {"transactions", transactions}
    };
}

inline void from_json(const nlohmann::json &j, CryptoNote::RawBlock &block)
{
    block.transactions.clear();

    std::string blockString = j.at("block").get<std::string>();

    block.block = Common::fromHex(blockString);

    std::vector<std::string> transactions = j.at("transactions").get<std::vector<std::string>>();

    for (const auto transaction : transactions)
    {
        block.transactions.push_back(Common::fromHex(transaction));
    }
}

}