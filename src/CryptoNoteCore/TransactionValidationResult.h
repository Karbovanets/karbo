// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The Galaxia Project Developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2016-2020, The Karbo developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <string>
#include <system_error>

namespace CryptoNote
{
    struct TransactionValidationResult 
    {
        /* A programmatic error code of the result */
        std::error_code errorCode;

        /* An error message describing the error code */
        std::string errorMessage;

        /* Whether the transaction is valid */
        bool valid = false;

        /* The fee of the transaction */
        uint64_t fee = 0;

        /* Is this transaction a fusion transaction */
        bool isFusionTransaction = false;
    };
}