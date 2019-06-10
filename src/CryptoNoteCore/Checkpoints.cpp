// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018, The TurtleCoin developers
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

#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <cstring>
#include <string>
#include <string.h>
#include <sstream>
#include <vector>
#include <iterator>

#include "../CryptoNoteConfig.h"
#include "Checkpoints.h"
#include "Common/StringTools.h"
#include "Common/DnsTools.h"

using namespace Logging;

namespace CryptoNote {
//---------------------------------------------------------------------------
Checkpoints::Checkpoints(Logging::ILogger &log) : logger(log, "checkpoints") {}
//---------------------------------------------------------------------------
bool Checkpoints::addCheckpoint(uint32_t index, const std::string &hash_str) {
  Crypto::Hash h = NULL_HASH;

  if (!Common::podFromHex(hash_str, h)) {
    logger(WARNING) << "Wrong hash in checkpoint for height " << index;
    return false;
  }

  if (!points.insert({ index, h }).second) {
    logger(WARNING) << "Checkpoint already exists for height" << index;
    return false;
  }

  points[index] = h;
  return true;
}
//---------------------------------------------------------------------------
bool Checkpoints::isInCheckpointZone(uint32_t index) const {
  return !points.empty() && (index <= (--points.end())->first);
}
//---------------------------------------------------------------------------
bool Checkpoints::checkBlock(uint32_t index, const Crypto::Hash &h,
                            bool& isCheckpoint) const {
  auto it = points.find(index);
  isCheckpoint = it != points.end();
  if (!isCheckpoint)
    return true;

  if (it->second == h) {
    logger(Logging::INFO, Logging::GREEN) 
      << "CHECKPOINT PASSED FOR INDEX " << index << " " << h;
    return true;
  } else {
    logger(Logging::WARNING, BRIGHT_YELLOW) << "CHECKPOINT FAILED FOR HEIGHT " << index
                                            << ". EXPECTED HASH: " << it->second
                                            << ", FETCHED HASH: " << h;
    return false;
  }
}
//---------------------------------------------------------------------------
bool Checkpoints::checkBlock(uint32_t index, const Crypto::Hash &h) const {
  bool ignored;
  return checkBlock(index, h, ignored);
}
//---------------------------------------------------------------------------
bool Checkpoints::isAlternativeBlockAllowed(uint32_t  blockchainSize,
                                            uint32_t  blockIndex) const {
  if (blockIndex == 0) {
    return false;
  }

  if (blockIndex < blockchainSize - CryptoNote::parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW
    && blockchainSize > CryptoNote::parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW
    && !isInCheckpointZone(blockIndex)) {
    logger(Logging::DEBUGGING, Logging::BRIGHT_WHITE)
      << "An attempt of too deep reorganization: "
      << blockchainSize - blockIndex << ", BLOCK REJECTED";

    return false;
  }

  auto it = points.upper_bound(blockchainSize);
  // Is blockchainSize before the first checkpoint?
  if (it == points.begin()) {
    return true;
  }

  --it;
  uint32_t checkpointIndex = it->first;
  return checkpointIndex < blockIndex;
}

std::vector<uint32_t> Checkpoints::getCheckpointHeights() const {
  std::vector<uint32_t> checkpointHeights;
  checkpointHeights.reserve(points.size());
  for (const auto& it : points) {
    checkpointHeights.push_back(it.first);
  }

  return checkpointHeights;
}
//---------------------------------------------------------------------------
bool Checkpoints::loadCheckpointsFromFile(const std::string& fileName) {
  std::ifstream file(fileName);
  if (!file) {
    logger(Logging::ERROR, BRIGHT_RED) << "Could not load checkpoints file: " << fileName;
    return false;
  }
  std::string indexString;
  std::string hash;
  uint32_t height;
  uint32_t count = 0;
  while (std::getline(file, indexString, ','), std::getline(file, hash)) {
  	try {
      height = std::stoi(indexString);
    }
    catch (const std::invalid_argument &) {
      logger(ERROR, BRIGHT_RED) << "Invalid checkpoint file format - "
          << "could not parse height as a number";
      return false;
    }
      if (!addCheckpoint(height, hash)) {
      return false;
    }
    ++count;
  }
  logger(Logging::INFO) << "Loaded " << count << " checkpoint(s) from " << fileName;
  return true;
}
//---------------------------------------------------------------------------
#ifndef __ANDROID__
bool Checkpoints::loadCheckpointsFromDns()
{
  std::string domain("checkpoints.karbo.org");
  std::vector<std::string>records;

  logger(Logging::INFO) << "Fetching DNS checkpoint records from " << domain;

  if (!Common::fetch_dns_txt(domain, records)) {
    logger(Logging::INFO) << "Failed to lookup DNS checkpoint records from " << domain;
  }

  for (const auto& record : records) {
    uint32_t height;
    Crypto::Hash hash = NULL_HASH;
    std::stringstream ss;

    size_t del = record.find_first_of(':');
    std::string height_str = record.substr(0, del), hash_str = record.substr(del + 1, 64);
    ss.str(height_str);
    ss >> height;
    char c;
    if (del == std::string::npos) continue;
    if ((ss.fail() || ss.get(c)) || !Common::podFromHex(hash_str, hash)) {
      logger(Logging::INFO) << "Failed to parse DNS checkpoint record: " << record;
      continue;
    }

    if (!(0 == points.count(height))) {
      logger(DEBUGGING) << "Checkpoint already exists for height: " << height << ". Ignoring DNS checkpoint.";
    }
    else {
      addCheckpoint(height, hash_str);
      logger(DEBUGGING) << "Added DNS checkpoint: " << height_str << ":" << hash_str;
    }
  }

  return true;
}
#endif
}