// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2024, The Karbo developers
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

#include <boost/program_options.hpp>

namespace CryptoNote {

class RpcServerConfig {
public:

  RpcServerConfig();

  static void initOptions(boost::program_options::options_description& desc);
  void init(const boost::program_options::variables_map& options);
  void setDataDir(std::string data_dir);
  bool isRestricted() const;
  bool isEnabledSSL() const;
  uint16_t getBindPort() const;
  uint16_t getBindPortSSL() const;
  std::string getBindIP() const;
  std::string getBindAddress() const;
  std::string getBindAddressSSL() const;
  std::string getDhFile() const;
  std::string getChainFile() const;
  std::string getKeyFile() const;
  std::string getNodeFeeAddress() const;
  uint64_t    getNodeFeeAmount() const;
  std::string getNodeFeeViewKey() const;
  std::string getContactInfo() const;
  std::vector<std::string> getCors() const;

private:
  bool        restrictedRPC;
  bool        enableSSL;
  uint16_t    bindPort;
  uint16_t    bindPortSSL;
  uint64_t    nodeFeeAmount = 0;
  std::string dataDir;
  std::string bindIp;
  std::string dhFile;
  std::string chainFile;
  std::string keyFile;
  std::string contactInfo;
  std::string nodeFeeAddress;
  std::string nodeFeeAmountStr;
  std::string nodeFeeViewKey;
  std::vector<std::string> enableCors;
};

}
