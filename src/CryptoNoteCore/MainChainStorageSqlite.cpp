// Copyright (c) 2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include "MainChainStorageSqlite.h"

#include <Common/FileSystemShim.h>

#include "json.hpp"

#include "CryptoNoteTools.h"

#include "sqlite3.h"

namespace CryptoNote
{
    MainChainStorageSqlite::MainChainStorageSqlite(const std::string &blocksFilename, const std::string &indexesFilename)
    {
        int resultCode = sqlite3_open(blocksFilename.c_str(), &m_db);

        if (resultCode != SQLITE_OK)
        {
            sqlite3_close(m_db);
            throw std::runtime_error("Failed to load main chain storage from " + blocksFilename + ": " + sqlite3_errmsg(m_db));
        }

        resultCode = sqlite3_exec(
                         m_db,
                         "CREATE TABLE IF NOT EXISTS `rawBlocks` ( `blockIndex` INTEGER NOT NULL DEFAULT 0 PRIMARY KEY AUTOINCREMENT, `rawBlock` TEXT )",
                         NULL,
                         NULL,
                         NULL
        );

        if (resultCode != SQLITE_OK)
        {
            sqlite3_close(m_db);
            throw std::runtime_error("Failed to create database table");
        }

        resultCode = sqlite3_exec(
                         m_db,
                         "CREATE INDEX IF NOT EXISTS `blockIndex` ON `rawBlocks` ( `blockIndex` )",
                         NULL,
                         NULL,
                         NULL
        );

        if (resultCode != SQLITE_OK)
        {
            sqlite3_close(m_db);
            throw std::runtime_error("Failed to create database indexes");
        }

        resultCode = sqlite3_exec(
                         m_db,
                         "PRAGMA synchronous = 0",
                         NULL,
                         NULL,
                         NULL
        );

        if (resultCode != SQLITE_OK)
        {
            sqlite3_close(m_db);
            throw std::runtime_error("Failed to set database PRAGMA");
        }
    }

    MainChainStorageSqlite::~MainChainStorageSqlite()
    {
        sqlite3_close(m_db);
    }

    void MainChainStorageSqlite::pushBlock(const RawBlock &rawBlock)
    {
        sqlite3_stmt *stmt;

        nlohmann::json rawBlockJson = rawBlock;

        std::string rawBlockHex = rawBlockJson.dump();

        const int resultCode = sqlite3_prepare_v2(m_db, "INSERT INTO rawBlocks (rawBlock) VALUES (?)", -1, &stmt, NULL);

        if (resultCode != SQLITE_OK)
        {
            sqlite3_close(m_db);
            throw std::runtime_error("Failed to prepare insert block statement");
        }

        sqlite3_bind_text(stmt, 1, rawBlockHex.c_str(), -1, 0);

        sqlite3_step(stmt);

        sqlite3_finalize(stmt);
    }

    void MainChainStorageSqlite::popBlock()
    {
        const int resultCode = sqlite3_exec(
                                  m_db,
                                  "DELETE FROM rawBlocks WHERE blockIndex = (SELECT MAX(blockIndex) FROM rawBlocks)",
                                  NULL,
                                  NULL,
                                  NULL
        );

        if (resultCode != SQLITE_OK)
        {
            sqlite3_close(m_db);
            throw std::runtime_error("Failed to pop the last block off the database");
        }
    }

    RawBlock MainChainStorageSqlite::getBlockByIndex(uint32_t index) const
    {
        sqlite3_stmt *stmt;
        RawBlock rawBlock = {};

        const uint32_t maxBlocks = getBlockCount();

        if (index > (maxBlocks - 1))
        {
            throw std::runtime_error("Cannot retrieve a block at an index higher than what we have");
        }

        int resultCode = sqlite3_prepare_v2(m_db, "SELECT rawBlock FROM rawBlocks WHERE blockIndex = ? LIMIT 1", -1, &stmt, NULL);

        sqlite3_bind_int(stmt, 1, index + 1);

        if (resultCode != SQLITE_OK)
        {
            sqlite3_close(m_db);
            throw std::runtime_error("Failed to prepare getBlockByIndex statement");
        }

        while((resultCode = sqlite3_step(stmt)) == SQLITE_ROW)
        {
            const std::string rawBlockString = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
            auto j = nlohmann::json::parse(rawBlockString);
            rawBlock = j.get<RawBlock>();
        }

        if (resultCode != SQLITE_DONE)
        {
            sqlite3_close(m_db);
            throw std::runtime_error("Failed to properly to retrieve rawBlock in getBlockByIndex");
        }

        sqlite3_finalize(stmt);

        return rawBlock;
    }

    uint32_t MainChainStorageSqlite::getBlockCount() const
    {
        sqlite3_stmt *stmt;
        size_t blockCount = 0;

        int resultCode = sqlite3_prepare_v2(m_db, "SELECT COUNT(*) AS blockCount FROM rawBlocks", -1, &stmt, NULL);

        if (resultCode != SQLITE_OK)
        {
            sqlite3_close(m_db);
            throw std::runtime_error("Failed to prepare getBlockCount statement");
        }

        while((resultCode = sqlite3_step(stmt)) == SQLITE_ROW)
        {
            blockCount = sqlite3_column_int(stmt, 0);
        }

        if (resultCode != SQLITE_DONE)
        {
            sqlite3_close(m_db);
            throw std::runtime_error("Failed to properly retrieve block count in getBlockCount");
        }

        sqlite3_finalize(stmt);

        return blockCount;
    }

    void MainChainStorageSqlite::clear()
    {
        const int resultCode = sqlite3_exec(
                                  m_db,
                                  "DELETE FROM rawBlocks",
                                  NULL,
                                  NULL,
                                  NULL
        );

        if (resultCode != SQLITE_OK)
        {
            sqlite3_close(m_db);
            throw std::runtime_error("Failed to delete all blocks from the database");
        }

        const int resultCodeReset = sqlite3_exec(
                                  m_db,
                                  "DELETE FROM sqlite_sequence WHERE name='rawBlocks'",
                                  NULL,
                                  NULL,
                                  NULL
        );

        if (resultCodeReset != SQLITE_OK)
        {
            sqlite3_close(m_db);
            throw std::runtime_error("Failed to reset the autoincroment value of the table");
        }
    }

    std::unique_ptr<IMainChainStorage> createSwappedMainChainStorageSqlite(const std::string &dataDir, const Currency &currency)
    {
        fs::path blocksFilename = fs::path(dataDir) / currency.blocksFileName();
        fs::path indexesFilename = fs::path(dataDir) / currency.blockIndexesFileName();

        auto storage = std::make_unique<MainChainStorageSqlite>(blocksFilename.string() + ".sqlite3", indexesFilename.string());

        if (storage->getBlockCount() == 0)
        {
            RawBlock genesisBlock;
            genesisBlock.block = toBinaryArray(currency.genesisBlock());
            storage->pushBlock(genesisBlock);
        }

        return storage;
    }
}