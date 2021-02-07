// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2016-2020, The Karbo developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <atomic>
#include <memory>
#include <string>

#include "leveldb/db.h"

#include "IDataBase.h"
#include "DataBaseConfig.h"

#include <Logging/LoggerRef.h>

namespace CryptoNote
{
    class LevelDBWrapper : public IDataBase
    {
      public:
        LevelDBWrapper(Logging::ILogger& logger, const DataBaseConfig& config);
        virtual ~LevelDBWrapper();

        LevelDBWrapper(const LevelDBWrapper &) = delete;
        LevelDBWrapper(LevelDBWrapper &&) = delete;

        LevelDBWrapper &operator=(const LevelDBWrapper &) = delete;
        LevelDBWrapper &operator=(LevelDBWrapper &&) = delete;

        void init() override;
        void shutdown() override;
        void destroy() override; // Be careful with this method!

        std::error_code write(IWriteBatch &batch) override;
        std::error_code writeSync(IWriteBatch& batch) override;
        std::error_code read(IReadBatch &batch) override;
        std::error_code readThreadSafe(IReadBatch &batch) override;

        void recreate() override;

      private:
        std::error_code write(IWriteBatch &batch, bool sync);

        std::string getDataDir(const DataBaseConfig &config);

        enum State
        {
            NOT_INITIALIZED,
            INITIALIZED
        };

        Logging::LoggerRef logger;
        std::unique_ptr<leveldb::DB> db;
        std::atomic<State> state;
  		  const DataBaseConfig m_config;
    };
} // namespace CryptoNote
