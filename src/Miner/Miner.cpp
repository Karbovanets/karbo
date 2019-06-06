// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2019, The Karbo Developers
//
// Please see the included LICENSE file for more information.

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "Miner.h"

#include <functional>

#include "crypto/crypto.h"
#include "CryptoNoteCore/CachedBlock.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteConfig.h"

#include <System/InterruptedException.h>

#define EPOCH 360 // 24 hours

namespace CryptoNote {

Miner::Miner(System::Dispatcher& dispatcher, Logging::ILogger& logger) :
  m_dispatcher(dispatcher),
  m_miningStopped(dispatcher),
  m_state(MiningState::MINING_STOPPED),
  m_logger(logger, "Miner") {
}

Miner::~Miner() {
  assert(m_state != MiningState::MINING_IN_PROGRESS);
}

BlockTemplate Miner::mine(const BlockMiningParameters& blockMiningParameters, size_t threadCount, uint64_t* dataset_64) {
  if (threadCount == 0) {
    throw std::runtime_error("Miner requires at least one thread");
  }

  if (m_state == MiningState::MINING_IN_PROGRESS) {
    throw std::runtime_error("Mining is already in progress");
  }

  m_state = MiningState::MINING_IN_PROGRESS;
  m_miningStopped.clear();

  runWorkers(blockMiningParameters, threadCount, dataset_64);

  assert(m_state != MiningState::MINING_IN_PROGRESS);
  if (m_state == MiningState::MINING_STOPPED) {
    m_logger(Logging::DEBUGGING) << "Mining has been stopped";
    throw System::InterruptedException();
  }

  assert(m_state == MiningState::BLOCK_FOUND);
  return m_block;
}

void Miner::stop() {
  MiningState state = MiningState::MINING_IN_PROGRESS;

  if (m_state.compare_exchange_weak(state, MiningState::MINING_STOPPED)) {
    m_miningStopped.wait();
    m_miningStopped.clear();
  }
}

void Miner::runWorkers(BlockMiningParameters blockMiningParameters, size_t threadCount, uint64_t* dataset_64) {
  assert(threadCount > 0);

  m_logger(Logging::INFO) << "Starting mining for difficulty " << blockMiningParameters.difficulty;

  try {
    blockMiningParameters.blockTemplate.nonce = Crypto::rand<uint32_t>();

    for (size_t i = 0; i < threadCount; ++i) {
      m_workers.emplace_back(std::unique_ptr<System::RemoteContext<void>>(
        new System::RemoteContext<void>(m_dispatcher, std::bind(&Miner::workerFunc, this, blockMiningParameters.blockTemplate, blockMiningParameters.difficulty, static_cast<uint32_t>(threadCount),  dataset_64)))
      );
	  m_logger(Logging::INFO) << "Thread " << i << " started at nonce: " << blockMiningParameters.blockTemplate.nonce;

      blockMiningParameters.blockTemplate.nonce++;
    }

    m_workers.clear();

  } catch (std::exception& e) {
    m_logger(Logging::ERROR) << "Error occurred during mining: " << e.what();
    m_state = MiningState::MINING_STOPPED;
  }

  m_miningStopped.set();
}

void Miner::workerFunc(const BlockTemplate& blockTemplate, uint64_t difficulty, uint32_t nonceStep, uint64_t* dataset_64) {
	try {
		BlockTemplate block = blockTemplate;
   	Crypto::cn_context cryptoContext;
		CachedBlock cachedBlock(block);
		if(block.majorVersion < BLOCK_MAJOR_VERSION_6){
			while (m_state == MiningState::MINING_IN_PROGRESS) {
				CachedBlock cachedBlock(block);
				Crypto::Hash hash = cachedBlock.getBlockLongHash(cryptoContext);
				if (check_hash(hash, difficulty)) {
					m_logger(Logging::INFO) << "Found block for difficulty " << difficulty;

					if (!setStateBlockFound()) {
						  m_logger(Logging::DEBUGGING) << "block is already found or mining stopped";
						  return;
					}
					m_block = block;
					return;
				}
				block.nonce += nonceStep;
			}
		} else{
			uint32_t height = cachedBlock.getBlockIndex();
			if(!dataset_64) exit(1);
			if(dataset_64[0] == 0 || height%EPOCH == 0){
				m_logger(Logging::INFO) << "Initialising dataset";
				Crypto::dataset_height(height, dataset_64);
				m_logger(Logging::INFO) << "Finished one-time initialisation";
			}
			m_logger(Logging::INFO) << "Started mining on dataset";
			Crypto::Hash hash;
			while (m_state == MiningState::MINING_IN_PROGRESS) {
				CachedBlock cachedBlock(block);
				hash = cachedBlock.getBlockSquashHash(cryptoContext, dataset_64);
				if (check_hash(hash, difficulty)) {
					m_logger(Logging::INFO) << "Found block for difficulty " << difficulty;

					if (!setStateBlockFound()) {
						m_logger(Logging::DEBUGGING) << "block is already found or mining stopped";
						return;
					}
					m_block = block;
					return;
				}
				block.nonce += nonceStep;
			}
		}
	} catch (std::exception& e) {
		m_logger(Logging::ERROR) << "Miner got error: " << e.what();
		m_state = MiningState::MINING_STOPPED;
		try{			
			free(dataset_64);
		} catch(std::exception& e) {
			;
		}	
	}
}

bool Miner::setStateBlockFound() {
  auto state = m_state.load();

  for (;;) {
    switch (state) {
      case MiningState::BLOCK_FOUND:
        return false;

      case MiningState::MINING_IN_PROGRESS:
        if (m_state.compare_exchange_weak(state, MiningState::BLOCK_FOUND)) {
          return true;
        }
        break;

      case MiningState::MINING_STOPPED:
        return false;

      default:
        assert(false);
        return false;
    }
  }
}

} //namespace CryptoNote
