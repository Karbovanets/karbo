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

#pragma once

#include <ctime>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <vector>

#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CachedBlock.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "CryptoNoteCore/IBlockchainCache.h"
#include "CryptoNoteCore/IMinerHandler.h"
#include "Serialization/ISerializer.h"
#include "Logging/ILogger.h"
#include "Logging/LoggerRef.h"

namespace CryptoNote {

	class BlobsCache {

	public:
		BlobsCache(Logging::ILogger& logger, IMinerHandler& handler);

		virtual ~BlobsCache() {
		}

		const uint32_t CURRENT_SERIALIZATION_VERSION = 1;
		
		bool getBlob(uint32_t blockIndex, BinaryArray& blob);
		void init();
		void clear();
		void pushBlob(const CachedBlock& cachedBlock);
		void popBlob();
		void load();
		void save();
		void rebuildBlobsCache();
		void rebuildBlobsCache(uint32_t splitBlockIndex, IBlockchainCache& newChain);
		void erase(uint32_t blockIndex);

		void serialize(ISerializer& s);

		typedef std::vector<BinaryArray> hashing_blobs_container;

	private:
		Logging::LoggerRef logger;
		IMinerHandler& m_handler;

		hashing_blobs_container m_blobs;
		const std::string blobsFilename = "hashingblobs.bin";
		std::recursive_mutex m_blobs_lock;

	};

}



