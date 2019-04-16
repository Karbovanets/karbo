// Copyright (c) 2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "IMainChainStorage.h"

#include "Currency.h"

#include "rocksdb/db.h"


namespace CryptoNote
{
    class MainChainStorageRocksdb : public IMainChainStorage
    {
        public:
            MainChainStorageRocksdb(const std::string &blocksFilename, const std::string &indexesFilename);

            virtual ~MainChainStorageRocksdb();

            virtual void pushBlock(const RawBlock &rawBlock) override;
            virtual void popBlock() override;

            virtual RawBlock getBlockByIndex(uint32_t index) const override;
            virtual uint32_t getBlockCount() const override;

            virtual void clear() override;

        private:
            rocksdb::DB* m_db;
            mutable std::atomic_int m_blockcount;
    };

    std::unique_ptr<IMainChainStorage> createSwappedMainChainStorageRocksdb(const std::string &dataDir, const Currency &currency);
}