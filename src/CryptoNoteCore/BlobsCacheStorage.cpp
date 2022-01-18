// Copyright (c) 2016-2022, The Karbo developers
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

#include "CryptoNoteCore/BlobsCacheStorage.h"

#include <ctime>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <vector>

#include "crypto/hash.h"

#include "Common/StdOutputStream.h"
#include "Common/StdInputStream.h"
#include "Common/PathTools.h"
#include "Common/Util.h"

namespace CryptoNote {
	
BlobsCache::BlobsCache(Logging::ILogger& _logger, IMinerHandler& handler) : logger(_logger, "BlobsCache"), m_handler(handler) {
    
}

void BlobsCache::serialize(ISerializer& s) {
    uint32_t version = CURRENT_SERIALIZATION_VERSION;
    s(version, "version");
    s(this->m_blobs, "hashing_blobs");
}

void BlobsCache::init() {
    load();

    if (m_blobs.size() == 0 || m_handler.getTopBlockIndex() + 1 != static_cast<uint32_t>(m_blobs.size())) {
        logger(Logging::INFO) << "Rebuild blobs cache because it's top block " << m_blobs.size() << " vs in DB " << m_handler.getTopBlockIndex() + 1;
        rebuildBlobsCache();
        save();
        logger(Logging::INFO) << "Rebuilding blobs cache complete";
    }
}

void BlobsCache::clear() {
    std::lock_guard<decltype(m_blobs_lock)> lk(m_blobs_lock);
    m_blobs.clear();
}

void BlobsCache::save() {
    std::lock_guard<decltype(m_blobs_lock)> lk(m_blobs_lock);
    std::string filename = Common::CombinePath(Tools::getDefaultDataDirectory(), blobsFilename);

    try {
        std::ofstream file(filename, std::ios::binary);
        if (!file) {
            return;
        }

        StdOutputStream stream(file);
        BinaryOutputStreamSerializer s(stream);
        CryptoNote::serialize(*this, s);
    }
    catch (std::exception& e) {
        logger(Logging::WARNING) << "Saving blobs cache failed: " << e.what();
    }
}

void BlobsCache::load() {
    std::lock_guard<decltype(m_blobs_lock)> lk(m_blobs_lock);
    std::string filename = Common::CombinePath(Tools::getDefaultDataDirectory(), blobsFilename);

    try {
        std::ifstream stdStream(filename, std::ios::binary);
        if (!stdStream) {
            logger(Logging::WARNING) << "Loading blobs cache failed: !stdStream";
            return;
        }

        StdInputStream stream(stdStream);
        BinaryInputStreamSerializer s(stream);
        CryptoNote::serialize(*this, s);
    }
    catch (std::exception& e) {
        logger(Logging::WARNING) << "loading failed: " << e.what();
        rebuildBlobsCache();
    }
}

void BlobsCache::pushBlob(const CachedBlock& cachedBlock) {
    BinaryArray ba = cachedBlock.getBlockHashingBinaryArray();
    std::lock_guard<decltype(m_blobs_lock)> lk(m_blobs_lock);
    m_blobs.push_back(ba);
}

void BlobsCache::popBlob() {
    std::lock_guard<decltype(m_blobs_lock)> lk(m_blobs_lock);
    m_blobs.pop_back();
}

void BlobsCache::rebuildBlobsCache() {
    std::chrono::steady_clock::time_point timePoint = std::chrono::steady_clock::now();
    m_blobs.clear();
    uint32_t top = m_handler.getTopBlockIndex() + 1;
    for (uint32_t i = 0; i < top; ++i) {
        if (i % 1000 == 0) {
            logger(Logging::INFO) << "Height " << i << " of " << top;
        }
        BlockTemplate block = m_handler.getBlockByIndex(i);
        CachedBlock cachedBlock(block);        
        pushBlob(cachedBlock);
    }
    std::chrono::duration<double> duration = std::chrono::steady_clock::now() - timePoint;
    logger(Logging::INFO) << "Rebuilding hashing blobs took: " << duration.count();
}

void BlobsCache::rebuildBlobsCache(uint32_t splitBlockIndex, IBlockchainCache& newChain) {
    assert(static_cast<uint32_t>(m_blobs.size()) >= splitBlockIndex);

    auto blocksToPop = static_cast<uint32_t>(m_blobs.size()) - splitBlockIndex;
    for (size_t i = 0; i < blocksToPop; ++i) {
        popBlob();
    }

    for (uint32_t index = splitBlockIndex; index <= newChain.getTopBlockIndex(); ++index) {
        auto rawBlock = newChain.getBlockByIndex(index);
        BlockTemplate block;
        bool br = fromBinaryArray(block, rawBlock.block);
        if (br) {}
        assert(br);
        CachedBlock cachedBlock(block);
        pushBlob(cachedBlock);
    }
}

void BlobsCache::erase(uint32_t blockIndex) {
    assert(static_cast<uint32_t>(m_blobs.size()) >= blockIndex);
    auto blocksToPop = static_cast<uint32_t>(m_blobs.size()) - blockIndex;
    for (size_t i = 0; i < blocksToPop; ++i) {
        popBlob();
    }
}

bool BlobsCache::getBlob(uint32_t blockIndex, BinaryArray& blob) {
    if (blockIndex < static_cast<uint32_t>(m_blobs.size())) {
        blob = m_blobs.at(blockIndex);
        
        return true;
    }

    return false;
}

}