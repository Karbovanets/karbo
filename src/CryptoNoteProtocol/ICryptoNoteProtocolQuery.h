// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2020, The Karbo developers
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

#include <cstddef>
#include <cstdint>
#include "P2p/ConnectionContext.h"

namespace CryptoNote {
class ICryptoNoteProtocolObserver;

class ICryptoNoteProtocolQuery {
public:
  virtual bool addObserver(ICryptoNoteProtocolObserver* observer) = 0;
  virtual bool removeObserver(ICryptoNoteProtocolObserver* observer) = 0;
  virtual ~ICryptoNoteProtocolQuery() {}
  virtual uint32_t getObservedHeight() const = 0;
  virtual size_t getPeerCount() const = 0;
  virtual bool isSynchronized() const = 0;
  virtual bool getConnections(std::vector<CryptoNoteConnectionContext>& connections) const = 0;
  virtual void printDandelions() const = 0;
};

} //namespace CryptoNote
