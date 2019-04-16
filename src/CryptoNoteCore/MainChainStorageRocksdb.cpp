// Copyright (c) 2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include "MainChainStorageRocksdb.h"

#include <Common/FileSystemShim.h>

#include "json.hpp"

#include "CryptoNoteTools.h"

#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "rocksdb/cache.h"
#include "rocksdb/table.h"

namespace CryptoNote
{
    MainChainStorageRocksdb::MainChainStorageRocksdb(const std::string &blocksFilename, const std::string &indexesFilename)
    {
        // setup db options
        rocksdb::DBOptions dbOpts;
        dbOpts.IncreaseParallelism();
        dbOpts.max_background_compactions = 2;
        dbOpts.create_if_missing = true;
        
        rocksdb::ColumnFamilyOptions cfOpts;
        cfOpts.compaction_style = rocksdb::kCompactionStyleLevel;
        cfOpts.compression_per_level.resize(cfOpts.num_levels);
        cfOpts.num_levels = 10;
        cfOpts.compression = rocksdb::kLZ4Compression;
        for (int i = 0; i < cfOpts.num_levels; ++i)
        {
            // per level compression: standar lz4
            cfOpts.compression_per_level[i] = rocksdb::kLZ4Compression;
        }
        rocksdb::BlockBasedTableOptions tblOpts;
        tblOpts.block_cache = rocksdb::NewLRUCache(32 * 1024 * 1024);
        std::shared_ptr<rocksdb::TableFactory> tf(NewBlockBasedTableFactory(tblOpts));
        cfOpts.table_factory = tf;
        
        rocksdb::Options options = rocksdb::Options(dbOpts, cfOpts);
        options.write_buffer_size = 256 * 1024 * 1024;
        cfOpts.max_write_buffer_number = 6;
        cfOpts.min_write_buffer_number_to_merge = 2;
        cfOpts.level0_file_num_compaction_trigger = 2;        
        
        // open DB
        rocksdb::Status s = rocksdb::DB::Open(options, blocksFilename, &m_db);
        if (!s.ok()) {
            throw std::runtime_error("Failed to load main chain storage from " + blocksFilename + ": " + s.ToString());
        }
        
        // initialize block count cache
        m_blockcount = getBlockCount();
    }

    MainChainStorageRocksdb::~MainChainStorageRocksdb()
    {
        m_db->Flush(rocksdb::FlushOptions());
        m_db->SyncWAL();
        delete m_db;
    }

    void MainChainStorageRocksdb::pushBlock(const RawBlock &rawBlock)
    {
        /* Convert the RawBlock to a json structure for easier storage */
        nlohmann::json rawBlockJson = rawBlock;
        std::string rawBlockHex = rawBlockJson.dump();

        const uint32_t nextBlockIndex = m_blockcount;
        m_blockcount++;
        
        rocksdb::WriteBatch batch;
        batch.Put(std::to_string(nextBlockIndex), rawBlockHex);
        batch.Put("count", std::to_string(m_blockcount));
        rocksdb::Status s = m_db->Write(rocksdb::WriteOptions(), &batch);
        
        if( !s.ok() ) {
            throw std::runtime_error("Failed to insert new block" + s.ToString());
        }
    }
    
    void MainChainStorageRocksdb::popBlock()
    {
        // @todo:
        // update the IMainChainStorage interface to pass desired block height
        // so we can perform range based deletion instead of delete one-by-one in a loop
        std::string count;
        rocksdb::Status s = m_db->Get(rocksdb::ReadOptions(), "count", &count);
        uint32_t new_count = std::stoi(count) - 1;
        
        if(s.ok())
        {
            rocksdb::WriteOptions write_options;
            write_options.sync = true;
            
            rocksdb::WriteBatch batch;
            batch.Delete(count);
            batch.Put("count", std::to_string(new_count));
            s = m_db->Write(write_options, &batch);
            if( !s.ok() )
            {
                throw std::runtime_error("Failed to pop the last block off the database: " + s.ToString());
            }
        }
        else 
        {
            throw std::runtime_error("Failed to pop the last block off the database: " + s.ToString());
        }
    }

    RawBlock MainChainStorageRocksdb::getBlockByIndex(uint32_t index) const
    {
        RawBlock rawBlock = {};

        auto key = std::to_string(index);
        std::string rawBlockString;
        rocksdb::Status s = m_db->Get(rocksdb::ReadOptions(), key, &rawBlockString);
        if (!s.ok())
        {
            throw std::runtime_error("Failed to get block by index" + s.ToString());
        }
        
        auto j = nlohmann::json::parse(rawBlockString);
        rawBlock = j.get<RawBlock>();
        return rawBlock;
    }

    uint32_t MainChainStorageRocksdb::getBlockCount() const
    {
        uint32_t blockCount = 0;
        
        std::string count;
        rocksdb::Status s = m_db->Get(rocksdb::ReadOptions(), "count", &count);

        if(s.ok())
        {
            blockCount = std::stoi(count);
        }
        else
        {
            rocksdb::WriteOptions write_options;
            write_options.sync = true;
            s = m_db->Put(write_options, "count", "0");
            if (!s.ok()) {
                throw std::runtime_error("Failed to get block count: " + s.ToString());
            }
        }
        
        m_blockcount = blockCount;
        return blockCount;
    }

    void MainChainStorageRocksdb::clear()
    {
        uint32_t last = getBlockCount();
        rocksdb::Slice start = "0";
        rocksdb::Slice end = std::to_string(last);
        auto cf = m_db->DefaultColumnFamily();
        rocksdb::Status s = m_db->DeleteRange(rocksdb::WriteOptions(), cf, start, end);
        if( !s.ok() ) {
            throw std::runtime_error("Failed to clear blocks: " + s.ToString());
        }
    }

    std::unique_ptr<IMainChainStorage> createSwappedMainChainStorageRocksdb(const std::string &dataDir, const Currency &currency)
    {
        fs::path blocksFilename = fs::path(dataDir) / currency.blocksFileName();
        fs::path indexesFilename = fs::path(dataDir) / currency.blockIndexesFileName();

        auto storage = std::make_unique<MainChainStorageRocksdb>(blocksFilename.string() + ".rocksdb", indexesFilename.string());

        if (storage->getBlockCount() == 0)
        {
            RawBlock genesisBlock;
            genesisBlock.block = toBinaryArray(currency.genesisBlock());
            storage->pushBlock(genesisBlock);
        }

        return storage;
    }
}