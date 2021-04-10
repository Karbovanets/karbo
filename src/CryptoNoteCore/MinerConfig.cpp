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

#include "MinerConfig.h"

#include "Common/CommandLine.h"

namespace CryptoNote {

namespace {
const command_line::arg_descriptor<std::string> arg_extra_messages   = { "extra-messages-file", "Specify file for extra messages to include into coinbase transactions", "", true };
const command_line::arg_descriptor<std::string> arg_mining_address   = { "mining-address", "Specify wallet address for mining", "", true };
const command_line::arg_descriptor<std::string> arg_mining_spend_key = { "mining-spend-key", "Specify corresponding secret spend key to sign the mined block", "", true };
const command_line::arg_descriptor<std::string> arg_mining_view_key  = { "mining-view-key", "Specify corresponding secret view key to sign the mined block", "", true };
const command_line::arg_descriptor<uint32_t>    arg_mining_threads   = { "mining-threads", "Specify mining threads count", 0, true };
}

MinerConfig::MinerConfig() {
  miningThreads = 0;
}

void MinerConfig::initOptions(boost::program_options::options_description& desc) {
  command_line::add_arg(desc, arg_extra_messages);
  command_line::add_arg(desc, arg_mining_address);
  command_line::add_arg(desc, arg_mining_spend_key);
  command_line::add_arg(desc, arg_mining_view_key);
  command_line::add_arg(desc, arg_mining_threads);
}

void MinerConfig::init(const boost::program_options::variables_map& options) {
  if(command_line::has_arg(options, arg_extra_messages)) {
    extraMessages = command_line::get_arg(options, arg_extra_messages);
  }

  if (command_line::has_arg(options, arg_mining_address)) {
    miningAddress = command_line::get_arg(options, arg_mining_address);
  }

  if (command_line::has_arg(options, arg_mining_spend_key)) {
    miningSpendKey = command_line::get_arg(options, arg_mining_spend_key);
  }
  
  if (command_line::has_arg(options, arg_mining_view_key)) {
    miningViewKey = command_line::get_arg(options, arg_mining_view_key);
  }

  if (command_line::has_arg(options, arg_mining_threads)) {
    miningThreads = command_line::get_arg(options, arg_mining_threads);
  }
}

} //namespace CryptoNote
