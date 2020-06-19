// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The Galaxia Project Developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2016-2020, The Karbo developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <system_error>

#include "CryptoNote.h"
#include "CachedTransaction.h"
#include "Currency.h"
#include "IBlockchainCache.h"
#include "TransactionValidationResult.h"
#include "Checkpoints/Checkpoints.h"
#include "Common/ThreadPool.h"

namespace CryptoNote
{

class TransactionValidator
{
    public:
        /////////////////
        /* CONSTRUCTOR */
        /////////////////
        TransactionValidator(
            const CryptoNote::CachedTransaction &cachedTransaction,
            CryptoNote::TransactionValidatorState &state,
            CryptoNote::IBlockchainCache *cache,
            const CryptoNote::Currency &currency,
            const CryptoNote::Checkpoints &checkpoints,
            Tools::ThreadPool &threadPool,
            const uint32_t blockHeight,
            const uint64_t blockSizeMedian,
            const uint64_t minFee,
            const bool isPoolTransaction);

        /////////////////////////////
        /* PUBLIC MEMBER FUNCTIONS */
        /////////////////////////////
        CryptoNote::TransactionValidationResult validate();

        CryptoNote::TransactionValidationResult revalidateAfterHeightChange();

    private:
        //////////////////////////////
        /* PRIVATE MEMBER FUNCTIONS */
        //////////////////////////////
        bool validateTransactionSize();

        bool validateTransactionInputs();

        bool validateTransactionOutputs();

        bool validateTransactionFee();

        bool validateTransactionExtra();

        bool validateInputOutputRatio();

        bool validateTransactionMixin();

        bool validateTransactionInputsExpensive();

        /////////////////////////
        /* PRIVATE MEMBER VARS */
        /////////////////////////
        const CryptoNote::Transaction m_transaction;

        const CryptoNote::CachedTransaction &m_cachedTransaction;

        CryptoNote::TransactionValidatorState &m_validatorState;

        const CryptoNote::IBlockchainCache *m_blockchainCache;

        const CryptoNote::Currency &m_currency;

        const CryptoNote::Checkpoints &m_checkpoints;

        const uint32_t m_blockHeight;

        const uint64_t m_blockSizeMedian;

        const uint64_t m_minFee;

        const bool m_isPoolTransaction;

        bool m_isFusion;

        CryptoNote::TransactionValidationResult m_validationResult;

        uint64_t m_sumOfOutputs = 0;
        uint64_t m_sumOfInputs = 0;

        Tools::ThreadPool &m_threadPool;
};

}