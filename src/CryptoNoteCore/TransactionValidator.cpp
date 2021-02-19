// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The Galaxia Project Developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2016-2020, The Karbo developers
//
// Please see the included LICENSE file for more information.

#include "CryptoTypes.h"
#include "crypto/crypto.h"
#include "../CryptoNoteConfig.h"
#include "CryptoNoteFormatUtils.h"
#include "CryptoNoteTools.h"
#include "TransactionValidationErrors.h"
#include "TransactionValidator.h"

namespace CryptoNote {

TransactionValidator::TransactionValidator(
    const CryptoNote::CachedTransaction &cachedTransaction,
    CryptoNote::TransactionValidatorState &state,
    CryptoNote::IBlockchainCache *cache,
    const CryptoNote::Currency &currency,
    const CryptoNote::Checkpoints &checkpoints,
    Utilities::ThreadPool<bool> &threadPool,
    const uint32_t blockHeight,
    const uint64_t blockSizeMedian,
    const uint64_t minFee,
    const bool isPoolTransaction):
    m_cachedTransaction(cachedTransaction),
    m_transaction(cachedTransaction.getTransaction()),
    m_validatorState(state),
    m_currency(currency),
    m_checkpoints(checkpoints),
    m_threadPool(threadPool),
    m_blockchainCache(cache),
    m_blockHeight(blockHeight),
    m_blockSizeMedian(blockSizeMedian),
    m_minFee(minFee),
    m_isPoolTransaction(isPoolTransaction),
    m_isFusion(false)
{
}

CryptoNote::TransactionValidationResult TransactionValidator::validate()
{
    /* Validate transaction isn't too big */
    if (!validateTransactionSize())
    {
        return m_validationResult;
    }

    /* Validate the transaction inputs are non empty, key images are valid, etc. */
    if (!validateTransactionInputs())
    {
        return m_validationResult;
    }

    /* Validate transaction outputs are non zero, don't overflow, etc */
    if (!validateTransactionOutputs())
    {
        return m_validationResult;
    }

    /* Verify inputs > outputs, fee is > min fee unless fusion, etc */
    if (!validateTransactionFee())
    {
        return m_validationResult;
    }

    /* Validate the transaction extra is a reasonable size. */
    if (!validateTransactionExtra())
    {
        return m_validationResult;
    }

    /* Validate transaction input / output ratio is not excessive */
    if (!validateInputOutputRatio())
    {
        return m_validationResult;
    }

    /* Validate transaction mixin is in the valid range */
    if (!validateTransactionMixin())
    {
        return m_validationResult;
    }

    /* Verify key images are not spent, ring signatures are valid, etc. We
     * do this separately from the transaction input verification, because
     * these checks are much slower to perform, so we want to fail fast on the
     * cheaper checks first. */
    if (!validateTransactionInputsExpensive())
    {
        return m_validationResult;
    }
    
    m_validationResult.valid = true;
    m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::VALIDATION_SUCCESS;

    return m_validationResult;
}

/* Note: Does not set the .fee property */
CryptoNote::TransactionValidationResult TransactionValidator::revalidateAfterHeightChange()
{
    /* Validate transaction isn't too big now that the median size has changed */
    if (!validateTransactionSize())
    {
        return m_validationResult;
    }

    /* Validate the transaction extra is still a reasonable size. */
    if (!validateTransactionExtra())
    {
        return m_validationResult;
    }

    /* Validate transaction mixin is still in the valid range */
    if (!validateTransactionMixin())
    {
        return m_validationResult;
    }

    m_validationResult.valid = true;
    m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::VALIDATION_SUCCESS;

    return m_validationResult;
}


bool TransactionValidator::validateTransactionSize()
{
    const auto maxTransactionSize = CryptoNote::parameters::MAX_TRANSACTION_SIZE_LIMIT;
    if (m_blockHeight > CryptoNote::parameters::UPGRADE_HEIGHT_V4 &&
        m_cachedTransaction.getTransactionBinaryArray().size() > maxTransactionSize)
    {
        m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::SIZE_TOO_LARGE;
        m_validationResult.errorMessage = "Transaction is too large (in bytes)";
        return false;
    }

    return true;
}

bool TransactionValidator::validateTransactionInputs()
{
    if (m_transaction.inputs.empty())
    {
        m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::EMPTY_INPUTS;
        m_validationResult.errorMessage = "Transaction has no inputs";

        return false;
    }

    uint64_t sumOfInputs = 0;

    std::unordered_set<Crypto::KeyImage> ki;

    for (const auto &input : m_transaction.inputs)
    {
        uint64_t amount = 0;

        if (input.type() == typeid(CryptoNote::KeyInput))
        {
            const CryptoNote::KeyInput &in = boost::get<CryptoNote::KeyInput>(input);
            amount = in.amount;

            if (!ki.insert(in.keyImage).second)
            {
                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_IDENTICAL_KEYIMAGES;
                m_validationResult.errorMessage = "Transaction contains identical key images";

                return false;
            }

            if (in.outputIndexes.empty())
            {
                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_EMPTY_OUTPUT_USAGE;
                m_validationResult.errorMessage = "Transaction contains no output indexes";

                return false;
            }

            /* outputIndexes are packed here, first is absolute, others are offsets to previous,
             * so first can be zero, others can't.
             * Fix discovered by Monero Lab and suggested by "fluffypony" (bitcointalk.org).
             * Skip this expensive validation in checkpoints zone. */
            if (!m_checkpoints.isInCheckpointZone(m_blockHeight + 1) && 
              !(scalarmultKey(in.keyImage, Crypto::EllipticCurveScalar2KeyImage(Crypto::L)) == Crypto::EllipticCurveScalar2KeyImage(Crypto::I)))
            {
                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_INVALID_DOMAIN_KEYIMAGES;
                m_validationResult.errorMessage = "Transaction contains key images in an invalid domain";

                return false;
            }

            if (std::find(++std::begin(in.outputIndexes), std::end(in.outputIndexes), 0)
                != std::end(in.outputIndexes))
            {
                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_IDENTICAL_OUTPUT_INDEXES;
                m_validationResult.errorMessage = "Transaction contains identical output indexes";

                return false;
            }

            if (!m_validatorState.spentKeyImages.insert(in.keyImage).second)
            {
                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_KEYIMAGE_ALREADY_SPENT;
                m_validationResult.errorMessage = "Transaction contains key image that has already been spent";

                return false;
            }
        }
        else if (input.type() == typeid(CryptoNote::MultisignatureInput)) {
            const CryptoNote::MultisignatureInput& in = boost::get<CryptoNote::MultisignatureInput>(input);
            CryptoNote::MultisignatureOutput output;
            uint64_t unlockTime = 0;
            if (!m_validatorState.spentMultisignatureGlobalIndexes.insert(std::make_pair(in.amount, in.outputIndex)).second) {
                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_MULTISIGNATURE_ALREADY_SPENT;
                m_validationResult.errorMessage = "Transaction uses spent multisignature";

                return false;
            }

            if (!m_blockchainCache->getMultisignatureOutputIfExists(in.amount, in.outputIndex, m_blockHeight, output, unlockTime)) {
                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_INVALID_GLOBAL_INDEX;
                m_validationResult.errorMessage = "Transaction has input with invalid global index";

                return false;
            }

            if (m_blockchainCache->checkIfSpentMultisignature(in.amount, in.outputIndex, m_blockHeight)) {
                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_MULTISIGNATURE_ALREADY_SPENT;
                m_validationResult.errorMessage = "Transaction uses spent multisignature";

                return false;
            }

            if (!m_blockchainCache->isTransactionSpendTimeUnlocked(unlockTime, m_blockHeight)) {
                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_SPEND_LOCKED_OUT;
                m_validationResult.errorMessage = "Transaction uses locked input";

                return false;
            }

            if (output.requiredSignatureCount != in.signatureCount) {
                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_WRONG_SIGNATURES_COUNT;
                m_validationResult.errorMessage = "Transaction has input with wrong signatures count";

                return false;
            }
        }
        else
        {
            m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_UNKNOWN_TYPE;
            m_validationResult.errorMessage = "Transaction input has an unknown input type";

            return false;
        }

        if (std::numeric_limits<uint64_t>::max() - amount < sumOfInputs)
        {
            m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUTS_AMOUNT_OVERFLOW;
            m_validationResult.errorMessage = "Transaction inputs will overflow";

            return false;
        }

        sumOfInputs += amount;
    }
    
    m_sumOfInputs = sumOfInputs;

    return true;
}

bool TransactionValidator::validateTransactionOutputs()
{
    uint64_t sumOfOutputs = 0;

    for (const auto &output : m_transaction.outputs)
    {
        if (output.amount == 0)
        {
            m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::OUTPUT_ZERO_AMOUNT;
            m_validationResult.errorMessage = "Transaction has an output amount of zero";

            return false;
        }

        if (m_blockHeight >= CryptoNote::parameters::UPGRADE_HEIGHT_V5)
        {
            if (!CryptoNote::is_valid_decomposed_amount(output.amount))
            {
                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::OUTPUT_INVALID_DECOMPOSED_AMOUNT;
                m_validationResult.errorMessage = "Invalid decomposed output amount (unmixable output)";

                return false;
            }
        }

        if (output.target.type() == typeid(CryptoNote::KeyOutput))
        {
            if (!Crypto::check_key(boost::get<CryptoNote::KeyOutput>(output.target).key))
            {
                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::OUTPUT_INVALID_KEY;
                m_validationResult.errorMessage = "Transaction output has an invalid output key";

                return false;
            }
        }
        else if (output.target.type() == typeid(CryptoNote::MultisignatureOutput))
        {
            const CryptoNote::MultisignatureOutput& multisignatureOutput = boost::get<CryptoNote::MultisignatureOutput>(output.target);
            if (multisignatureOutput.requiredSignatureCount > multisignatureOutput.keys.size()) {
                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::OUTPUT_INVALID_REQUIRED_SIGNATURES_COUNT;
                m_validationResult.errorMessage = "Transaction has output with invalid signatures count";
                return false;
            }

            for (const Crypto::PublicKey& key : multisignatureOutput.keys) {
                if (!Crypto::check_key(key)) {
                    m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::OUTPUT_INVALID_MULTISIGNATURE_KEY;
                    m_validationResult.errorMessage = "Transaction has output with invalid multisignature key";
                    return false;
                }
            }
        }
        else
        {
            m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::OUTPUT_UNKNOWN_TYPE;
            m_validationResult.errorMessage = "Transaction output has an unknown output type";

            return false;
        }

        if (std::numeric_limits<uint64_t>::max() - output.amount < sumOfOutputs)
        {
            m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::OUTPUTS_AMOUNT_OVERFLOW;
            m_validationResult.errorMessage = "Transaction outputs will overflow";

            return false;
        }

        sumOfOutputs += output.amount;
    }

    m_sumOfOutputs = sumOfOutputs;

    return true;
}

/**
 * Pre-requisite - Call validateTransactionInputs() and validateTransactionOutputs()
 * to ensure m_sumOfInputs and m_sumOfOutputs is set
 */
bool TransactionValidator::validateTransactionFee()
{
    if (m_sumOfInputs == 0)
    {
        throw std::runtime_error(
            "Error! You must call validateTransactionInputs() and "
            "validateTransactionOutputs() before calling validateTransactionFee()!"
        );
    }

    if (m_sumOfOutputs > m_sumOfInputs)
    {
        m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::WRONG_AMOUNT;
        m_validationResult.errorMessage = "Sum of outputs is greater than sum of inputs";

        return false;
    }

    const uint64_t fee = m_sumOfInputs - m_sumOfOutputs;

    m_isFusion = fee == 0 && m_currency.isFusionTransaction(
        m_transaction,
        m_cachedTransaction.getTransactionBinaryArray().size(),
        m_blockHeight
    );

    if (!m_isFusion)
    {
        if (m_blockHeight <= CryptoNote::parameters::UPGRADE_HEIGHT_V3_1 && fee < CryptoNote::parameters::MINIMUM_FEE_V1
            ||
            m_blockHeight > CryptoNote::parameters::UPGRADE_HEIGHT_V3_1 && m_blockHeight <= CryptoNote::parameters::UPGRADE_HEIGHT_V4 && fee < CryptoNote::parameters::MINIMUM_FEE_V2
            ||
            m_blockHeight > CryptoNote::parameters::UPGRADE_HEIGHT_V4 && (fee < (m_minFee - (m_minFee * 20 / 100))))
        {
            m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INVALID_FEE;
            m_validationResult.errorMessage = "Transaction fee is below minimum fee and is not a fusion transaction";
            return false;
        }
    }

    m_validationResult.fee = fee;

    return true;
}

bool TransactionValidator::validateTransactionExtra()
{
    // Karbo's fee per byte for Extra
    if (m_blockHeight > CryptoNote::parameters::UPGRADE_HEIGHT_V4_2)
    {
        uint64_t min = m_minFee;
        uint64_t extraSize = (uint64_t)m_transaction.extra.size();
        uint64_t feePerByte = m_currency.getFeePerByte(extraSize, m_minFee);
        min += feePerByte;
        if (m_validationResult.fee < (min - min * 20 / 100) && !m_isFusion)
        {
            m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INVALID_FEE;
            m_validationResult.errorMessage = "Transaction fee is insufficient due to additional data in extra";

            return false;
        }
    }

    return true;
}

bool TransactionValidator::validateInputOutputRatio()
{
    // do nothing
    return true;
}

bool TransactionValidator::validateTransactionMixin()
{
    uint64_t mixin = 0;
    for (const auto &input : m_transaction.inputs)
    {
        if (input.type() != typeid(CryptoNote::KeyInput))
            continue;

        uint64_t currentMixin = boost::get<CryptoNote::KeyInput>(input).outputIndexes.size();
        if (currentMixin > mixin)
        {
           mixin = currentMixin;
        }
    }

    if ((m_blockHeight > CryptoNote::parameters::UPGRADE_HEIGHT_V3_1 && mixin > m_currency.maxMixin()) ||
        (m_blockHeight > m_currency.upgradeHeightV4() && mixin < m_currency.minMixin() && mixin != 1))
    {
         m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INVALID_MIXIN;
         m_validationResult.errorMessage = "Transaction has wrong mixin";
    }

    return true;
}

bool TransactionValidator::validateTransactionInputsExpensive()
{
    /* Don't need to do expensive transaction validation for transactions
     * in a checkpoints range - they are assumed valid, and the transaction
     * hash would change thus invalidation the checkpoints if not. */
    if (m_checkpoints.isInCheckpointZone(m_blockHeight + 1))
    {
        return true;
    }

    uint64_t inputIndex = 0;

    std::vector<std::future<bool>> validationResults;
    std::atomic<bool> cancelValidation(false);
    const Crypto::Hash prefixHash = m_cachedTransaction.getTransactionPrefixHash();

    for (const auto &input : m_transaction.inputs)
    {
        /* Validate each input on a separate thread in our thread pool */
                        //emplace_back
        validationResults.push_back(m_threadPool.addJob([inputIndex, &input, &prefixHash, &cancelValidation, this] {

            if (cancelValidation.load())
            {
                return false; // fail the validation immediately if cancel requested
            }

            // get recent blocks for stake validation
            std::vector<BlockTemplate> blocks;
            if (m_blockHeight > CryptoNote::parameters::UPGRADE_HEIGHT_V5) {
                for (auto i = m_blockHeight - 1; i <= m_blockHeight - CryptoNote::parameters::EXPECTED_NUMBER_OF_BLOCKS_PER_DAY; --i) {
                    RawBlock rawBlock = m_blockchainCache->getBlockByIndex(i);

                    BlockTemplate blockTemplate;
                    if (!fromBinaryArray(blockTemplate, rawBlock.block)) {
                        throw std::runtime_error("Coulnd't deserialize BlockTemplate");
                    }

                    if (blockTemplate.majorVersion >= BLOCK_MAJOR_VERSION_5) {
                        break;
                    }

                    blocks.push_back(blockTemplate);
                }
            }

            if (input.type() == typeid(CryptoNote::KeyInput)) {
                const CryptoNote::KeyInput &in = boost::get<CryptoNote::KeyInput>(input);

                if (m_blockchainCache->checkIfSpent(in.keyImage, m_blockHeight))
                {
                    m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_KEYIMAGE_ALREADY_SPENT;
                    m_validationResult.errorMessage = "Transaction contains key image that has already been spent";

                    return false;
                }

                std::vector<Crypto::PublicKey> outputKeys;
                std::vector<uint32_t> globalIndexes(in.outputIndexes.size());

                globalIndexes[0] = in.outputIndexes[0];

                /* Convert output indexes from relative to absolute */
                for (size_t i = 1; i < in.outputIndexes.size(); ++i)
                {
                    globalIndexes[i] = globalIndexes[i - 1] + in.outputIndexes[i];
                }

                const auto result = m_blockchainCache->extractKeyOutputKeys(
                    in.amount,
                    m_blockHeight,
                    { globalIndexes.data(), globalIndexes.size() },
                    outputKeys
                );

                if (result == CryptoNote::ExtractOutputKeysResult::INVALID_GLOBAL_INDEX)
                {
                    m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_INVALID_GLOBAL_INDEX;
                    m_validationResult.errorMessage = "Transaction contains invalid global indexes";

                    return false;
                }

                if (result == CryptoNote::ExtractOutputKeysResult::OUTPUT_LOCKED)
                {
                    m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_SPEND_LOCKED_OUT;
                    m_validationResult.errorMessage = "Transaction includes an input which is still locked";

                    return false;
                }

                if (outputKeys.size() != m_transaction.signatures[inputIndex].size())
                {
                    m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_INVALID_SIGNATURES_COUNT;
                    m_validationResult.errorMessage = "Transaction has an invalid number of signatures";

                    return false;
                }

                std::vector<const Crypto::PublicKey*> outputKeyPointers;
                outputKeyPointers.reserve(outputKeys.size());
                std::for_each(outputKeys.begin(), outputKeys.end(), [&outputKeyPointers](const Crypto::PublicKey& key) { outputKeyPointers.push_back(&key); });
                if (!Crypto::check_ring_signature(prefixHash, in.keyImage, outputKeyPointers.data(),
                    outputKeyPointers.size(), m_transaction.signatures[inputIndex].data(),
                    m_blockHeight > CryptoNote::parameters::KEY_IMAGE_CHECKING_BLOCK_INDEX))
                {
                    m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_INVALID_SIGNATURES;
                    m_validationResult.errorMessage = "Transaction contains invalid signatures";

                    return false;
                }

                // validate against spending fresh stake
                if (m_blockHeight > CryptoNote::parameters::UPGRADE_HEIGHT_V5) {
                    for (const auto& b : blocks) {
                        for (const auto& c : b.stake.reserve_proof.proofs) {
                            if (c.key_image == in.keyImage) {
                                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_SPEND_LOCKED_OUT;
                                m_validationResult.errorMessage = "Transaction includes an input from recently mining stake";

                                return false;
                            }
                        }
                    }
                }

            } else if (input.type() == typeid(CryptoNote::MultisignatureInput)) {
                const CryptoNote::MultisignatureInput& in = boost::get<CryptoNote::MultisignatureInput>(input);
                CryptoNote::MultisignatureOutput output;
           
                size_t inputSignatureIndex = 0;
                size_t outputKeyIndex = 0;
                while (inputSignatureIndex < in.signatureCount) {
                    if (outputKeyIndex == output.keys.size()) {
                        m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_INVALID_SIGNATURES;
                        m_validationResult.errorMessage = "Transaction has input with invalid signature";

                        return false;
                    }

                    if (Crypto::check_signature(prefixHash, output.keys[outputKeyIndex],
                        m_transaction.signatures[inputIndex][inputSignatureIndex])) {
                        ++inputSignatureIndex;
                    }

                    ++outputKeyIndex;
                }
            }
            else {
                assert(false);
                m_validationResult.errorCode = CryptoNote::error::TransactionValidationError::INPUT_UNKNOWN_TYPE;
                m_validationResult.errorMessage = "Transaction has input with unknown type";

                return false;
            }

            return true;

        }));

        inputIndex++;
    }

    bool valid = true;

    for (auto &result : validationResults)
    {
        if (!result.get())
        {
            valid = false;
            cancelValidation.store(true);
        }
    }

    return valid;
}

}