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

#pragma once

#include <cstdint>
#include <algorithm>
#include <iterator>
#include <Common/StringTools.h>
#include "json.hpp"

using namespace Common;

namespace Crypto {

struct Hash {
  uint8_t data[32];
};

struct PublicKey {
  uint8_t data[32];
};

struct SecretKey {
  uint8_t data[32];
};

struct KeyDerivation {
  uint8_t data[32];
};

struct KeyImage {
  uint8_t data[32];
};

struct Signature {
  uint8_t data[64];
};


inline void from_json(const nlohmann::json &j, Crypto::Hash &h)
{
  if (!Common::podFromHex(j.get<std::string>(), h.data))
  {
    const auto err = nlohmann::detail::parse_error::create(
      100, 0, "Wrong length or not hex!"
    );

    throw nlohmann::json::parse_error(err);
  }
}

inline void to_json(nlohmann::json &j, const Crypto::PublicKey &p)
{
  j = Common::podToHex(p);
}

inline void from_json(const nlohmann::json &j, Crypto::PublicKey &p)
{
  if (!Common::podFromHex(j.get<std::string>(), p.data))
  {
    const auto err = nlohmann::detail::parse_error::create(
      100, 0, "Wrong length or not hex!"
    );

    throw nlohmann::json::parse_error(err);
  }
}

inline void to_json(nlohmann::json &j, const Crypto::SecretKey &s)
{
  j = Common::podToHex(s);
}

inline void from_json(const nlohmann::json &j, Crypto::SecretKey &s)
{
  if (!Common::podFromHex(j.get<std::string>(), s.data))
  {
    const auto err = nlohmann::detail::parse_error::create(
      100, 0, "Wrong length or not hex!"
    );

    throw nlohmann::json::parse_error(err);
  }
}

inline void to_json(nlohmann::json &j, const Crypto::KeyDerivation &k)
{
  j = Common::podToHex(k);
}

inline void from_json(const nlohmann::json &j, Crypto::KeyDerivation &k)
{
  if (!Common::podFromHex(j.get<std::string>(), k.data))
  {
    const auto err = nlohmann::detail::parse_error::create(
      100, 0, "Wrong length or not hex!"
    );

    throw nlohmann::json::parse_error(err);
  }
}

inline void to_json(nlohmann::json &j, const Crypto::KeyImage &k)
{
  j = Common::podToHex(k);
}

inline void from_json(const nlohmann::json &j, Crypto::KeyImage &k)
{
  if (!Common::podFromHex(j.get<std::string>(), k.data))
  {
    const auto err = nlohmann::detail::parse_error::create(
      100, 0, "Wrong length or not hex!"
    );

    throw nlohmann::json::parse_error(err);
  }
}

}
