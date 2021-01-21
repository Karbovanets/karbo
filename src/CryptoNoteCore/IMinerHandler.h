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

#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "CryptoNoteCore/Difficulty.h"

namespace CryptoNote {
  struct IMinerHandler {
    virtual bool handleBlockFound(BlockTemplate& b) = 0;
    virtual bool getBlockTemplate(BlockTemplate& b, const AccountPublicAddress& adr, const BinaryArray& extraNonce, const ReserveProof& reserveProof, Difficulty& difficulty, uint32_t& height) const = 0;
    virtual bool getBlockLongHash(Crypto::cn_context &context, const CachedBlock& block, Crypto::Hash& res) = 0;
    virtual bool checkReserveProof(const ReserveProof& proof, const CryptoNote::AccountPublicAddress& address, std::string& message, uint32_t height, uint64_t& total, uint64_t& spent) = 0;
    virtual bool getBaseStake(const uint32_t height, uint64_t& stake) = 0;
    virtual uint64_t getBaseStake() = 0;
    virtual uint32_t getCurrentBlockchainHeight() const = 0;

  protected:
    ~IMinerHandler() {}
  };
}
