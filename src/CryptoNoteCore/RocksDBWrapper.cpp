// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin developers
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

#include "RocksDBWrapper.h"

#include "rocksdb/cache.h"
#include "rocksdb/table.h"
#include "rocksdb/db.h"
#include "rocksdb/utilities/backupable_db.h"

#include "DataBaseErrors.h"

using namespace CryptoNote;
using namespace Logging;

namespace {
  const std::string DB_NAME = "DB";
  const std::string TESTNET_DB_NAME = "testnet_DB";
}

RocksDBWrapper::RocksDBWrapper(Logging::ILogger& logger, const DataBaseConfig &config) : 
  logger(logger, "RocksDBWrapper"), m_config(config), state(NOT_INITIALIZED){

}

RocksDBWrapper::~RocksDBWrapper() {

}

void RocksDBWrapper::init() {
  if (state.load() != NOT_INITIALIZED) {
    throw std::system_error(make_error_code(CryptoNote::error::DataBaseErrorCodes::ALREADY_INITIALIZED));
  }
  
  std::string dataDir = getDataDir(m_config);

  logger(INFO) << "Opening DB in " << dataDir;

  rocksdb::DB* dbPtr;

  rocksdb::Options dbOptions = getDBOptions(m_config);
  rocksdb::Status status = rocksdb::DB::Open(dbOptions, dataDir, &dbPtr);
  if (status.ok()) {
    logger(INFO) << "DB opened in " << dataDir;
  } else if (!status.ok() && status.IsInvalidArgument()) {
    logger(INFO) << "DB not found in " << dataDir << ". Creating new DB...";
    dbOptions.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::Open(dbOptions, dataDir, &dbPtr);
    if (!status.ok()) {
      logger(ERROR) << "DB Error. DB can't be created in " << dataDir << ". Error: " << status.ToString();
      throw std::system_error(make_error_code(CryptoNote::error::DataBaseErrorCodes::INTERNAL_ERROR));
    }
  } else if (status.IsIOError()) {
    logger(ERROR) << "DB Error. DB can't be opened in " << dataDir << ". Error: " << status.ToString();
    throw std::system_error(make_error_code(CryptoNote::error::DataBaseErrorCodes::IO_ERROR));
  } else {
    logger(ERROR) << "DB Error. DB can't be opened in " << dataDir << ". Error: " << status.ToString();
    throw std::system_error(make_error_code(CryptoNote::error::DataBaseErrorCodes::INTERNAL_ERROR));
  }

  db.reset(dbPtr);
  state.store(INITIALIZED);
}

void RocksDBWrapper::shutdown() {
  if (state.load() != INITIALIZED) {
    throw std::system_error(make_error_code(CryptoNote::error::DataBaseErrorCodes::NOT_INITIALIZED));
  }

  logger(INFO) << "Closing DB.";
  db->Flush(rocksdb::FlushOptions());
  db->SyncWAL();
  db.reset();
  state.store(NOT_INITIALIZED);
}

void RocksDBWrapper::destroy() {
  if (state.load() != NOT_INITIALIZED) {
    throw std::system_error(make_error_code(CryptoNote::error::DataBaseErrorCodes::ALREADY_INITIALIZED));
  }

  std::string dataDir = getDataDir(m_config);

  logger(WARNING) << "Destroying DB in " << dataDir;

  rocksdb::Options dbOptions = getDBOptions(m_config);
  rocksdb::Status status = rocksdb::DestroyDB(dataDir, dbOptions);

  if (status.ok()) {
    logger(WARNING) << "DB destroyed in " << dataDir;
  } else {
    logger(ERROR) << "DB Error. DB can't be destroyed in " << dataDir << ". Error: " << status.ToString();
    throw std::system_error(make_error_code(CryptoNote::error::DataBaseErrorCodes::INTERNAL_ERROR));
  }
}

std::error_code RocksDBWrapper::write(IWriteBatch& batch) {
  if (state.load() != INITIALIZED) {
    throw std::system_error(make_error_code(CryptoNote::error::DataBaseErrorCodes::NOT_INITIALIZED));
  }

  return write(batch, false);
}

std::error_code RocksDBWrapper::writeSync(IWriteBatch& batch) {
  if (state.load() != INITIALIZED) {
    throw std::system_error(make_error_code(CryptoNote::error::DataBaseErrorCodes::NOT_INITIALIZED));
  }

  return write(batch, true);
}

std::error_code RocksDBWrapper::write(IWriteBatch& batch, bool sync) {
  rocksdb::WriteOptions writeOptions;
  writeOptions.sync = sync;

  rocksdb::WriteBatch rocksdbBatch;
  std::vector<std::pair<std::string, std::string>> rawData(batch.extractRawDataToInsert());
  for (const std::pair<std::string, std::string>& kvPair : rawData) {
    rocksdbBatch.Put(rocksdb::Slice(kvPair.first), rocksdb::Slice(kvPair.second));
  }

  std::vector<std::string> rawKeys(batch.extractRawKeysToRemove());
  for (const std::string& key : rawKeys) {
    rocksdbBatch.Delete(rocksdb::Slice(key));
  }

  rocksdb::Status status = db->Write(writeOptions, &rocksdbBatch);

  if (!status.ok()) {
    logger(ERROR) << "Can't write to DB. " << status.ToString();
    return make_error_code(CryptoNote::error::DataBaseErrorCodes::INTERNAL_ERROR);
  } else {
    return std::error_code();
  }
}

std::error_code RocksDBWrapper::read(IReadBatch& batch) {
  if (state.load() != INITIALIZED) {
    throw std::runtime_error("Not initialized.");
  }

  rocksdb::ReadOptions readOptions;

  std::vector<std::string> rawKeys(batch.getRawKeys());
  std::vector<rocksdb::Slice> keySlices;
  keySlices.reserve(rawKeys.size());
  for (const std::string& key : rawKeys) {
    keySlices.emplace_back(rocksdb::Slice(key));
  }

  std::vector<std::string> values;
  values.reserve(rawKeys.size());
  std::vector<rocksdb::Status> statuses = db->MultiGet(readOptions, keySlices, &values);

  std::error_code error;
  std::vector<bool> resultStates;
  for (const rocksdb::Status& status : statuses) {
    if (!status.ok() && !status.IsNotFound()) {
      return make_error_code(CryptoNote::error::DataBaseErrorCodes::INTERNAL_ERROR);
    }
    resultStates.push_back(status.ok());
  }

  batch.submitRawResult(values, resultStates);
  return std::error_code();
}

std::error_code RocksDBWrapper::readThreadSafe(IReadBatch &batch) {
  if (state.load() != INITIALIZED) {
    throw std::runtime_error("Not initialized.");
  }

  rocksdb::ReadOptions readOptions;
  std::vector<std::string> rawKeys(batch.getRawKeys());
  std::vector<std::string> values(rawKeys.size());
  std::vector<bool> resultStates;
  int i = 0;
  for (const std::string &key : rawKeys) {
    const rocksdb::Status status = db->Get(readOptions, rocksdb::Slice(key), &values[i]);
    if (status.ok()) {
      resultStates.push_back(true);
    } else {
      if (!status.IsNotFound()) {
        return make_error_code(CryptoNote::error::DataBaseErrorCodes::INTERNAL_ERROR);
      }

      resultStates.push_back(false);
    }
    i++;
  }

  batch.submitRawResult(values, resultStates);
  return std::error_code();
}

rocksdb::Options RocksDBWrapper::getDBOptions(const DataBaseConfig &config) {
  rocksdb::DBOptions dbOptions;
  dbOptions.IncreaseParallelism(config.getBackgroundThreadsCount());
  dbOptions.info_log_level = rocksdb::InfoLogLevel::WARN_LEVEL;
  dbOptions.max_open_files = config.getMaxOpenFiles();

  dbOptions.max_total_wal_size = (uint64_t)1024000;
  dbOptions.db_write_buffer_size = (uint64_t)81920000;

  rocksdb::ColumnFamilyOptions fOptions;
  fOptions.write_buffer_size = static_cast<size_t>(config.getWriteBufferSize());
  // merge two memtables when flushing to L0
  fOptions.min_write_buffer_number_to_merge = 2;
  // this means we'll use 50% extra memory in the worst case, but will reduce
  // write stalls.
  fOptions.max_write_buffer_number = 2; // 6
  // start flushing L0->L1 as soon as possible. each file on level0 is
  // (memtable_memory_budget / 2). This will flush level 0 when it's bigger than
  // memtable_memory_budget.
  fOptions.level0_file_num_compaction_trigger = 20;

  fOptions.level0_slowdown_writes_trigger = 30;
  fOptions.level0_stop_writes_trigger = 40;

  // doesn't really matter much, but we don't want to create too many files
  fOptions.target_file_size_base = config.getWriteBufferSize() / 10;
  // make Level1 size equal to Level0 size, so that L0->L1 compactions are fast
  fOptions.max_bytes_for_level_base = config.getWriteBufferSize();
  fOptions.num_levels = 10;
  fOptions.target_file_size_multiplier = 2;
  // level style compaction
  fOptions.compaction_style = rocksdb::kCompactionStyleLevel;

  fOptions.compression_per_level.resize(fOptions.num_levels);
  if(!config.getCompressionEnabled())
  {
    fOptions.compression = rocksdb::kZSTD;
  }
  
  for (int i = 0; i < fOptions.num_levels; ++i) {
    if(!config.getCompressionEnabled())
    {
      fOptions.compression_per_level[i] = rocksdb::kNoCompression;
    }
    else
    {
      if(i < 2) {
        fOptions.compression_per_level[i] = rocksdb::kNoCompression;
      } else {
        fOptions.compression_per_level[i] = rocksdb::kZSTD;
      }
    }
  }


  rocksdb::BlockBasedTableOptions tableOptions;
  tableOptions.block_cache = rocksdb::NewLRUCache(config.getReadCacheSize());
  std::shared_ptr<rocksdb::TableFactory> tfp(NewBlockBasedTableFactory(tableOptions));
  fOptions.table_factory = tfp;

  return rocksdb::Options(dbOptions, fOptions);
}

std::string RocksDBWrapper::getDataDir(const DataBaseConfig& config) {
  if (config.getTestnet()) {
    return config.getDataDir() + '/' + TESTNET_DB_NAME;
  } else {
    return config.getDataDir() + '/' + DB_NAME;
  }
}
