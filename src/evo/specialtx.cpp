// Copyright (c) 2018 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "clientversion.h"
#include "consensus/validation.h"
#include "hash.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "validation.h"

#include "cbtx.h"
#include "deterministicmns.h"
#include "specialtx.h"
#include "concepttx.h"
#include "nuancetx.h"
#include "mcptx.h"

#include "llmq/quorums_blockprocessor.h"
#include "llmq/quorums_commitment.h"


bool CheckSpecialTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nVersion != 3 || tx.nType == TRANSACTION_NORMAL)
        return true;

    if (pindexPrev && VersionBitsState(pindexPrev, Params().GetConsensus(), Consensus::DEPLOYMENT_DIP0003, versionbitscache) != THRESHOLD_ACTIVE) {
        return state.DoS(10, false, REJECT_INVALID, "bad-tx-type");
    }

    switch (tx.nType) {
    case TRANSACTION_PROVIDER_REGISTER:
        return CheckProRegTx(tx, pindexPrev, state);
    case TRANSACTION_PROVIDER_UPDATE_SERVICE:
        return CheckProUpServTx(tx, pindexPrev, state);
    case TRANSACTION_PROVIDER_UPDATE_REGISTRAR:
        return CheckProUpRegTx(tx, pindexPrev, state);
    case TRANSACTION_PROVIDER_UPDATE_REVOKE:
        return CheckProUpRevTx(tx, pindexPrev, state);
    case TRANSACTION_QUORUM_COMMITMENT:
        return llmq::CheckLLMQCommitment(tx, pindexPrev, state);
    case TRANSACTION_COINBASE:
        return CheckCbTx(tx, pindexPrev, state);
    case TRANSACTION_CONCEPT_REGISTER:
        return CheckConRegTx(tx, pindexPrev, state);
    case TRANSACTION_CONCEPT_UNREGISTER:
        return CheckConUnregTx(tx, pindexPrev, state);
    case TRANSACTION_CONCEPT_AUTHORIZE:
        return CheckConAuthTx(tx, pindexPrev, state);
    case TRANSACTION_CONCEPT_REVOKE:
        return CheckConRevAuthTx(tx, pindexPrev, state);
    case TRANSACTION_CONCEPT_UPDATE:
        return CheckConUpTx(tx, pindexPrev, state);
    case TRANSACTION_CONCEPT_TRANSFER:
        return CheckConXferTx(tx, pindexPrev, state);
    case TRANSACTION_NUANCE_REGISTER:
        return CheckNuRegTx(tx, pindexPrev, state);
    case TRANSACTION_NUANCE_UNREGISTER:
        return CheckNuUnregTx(tx, pindexPrev, state);
    case TRANSACTION_NUANCE_AUTHORIZE:
        return CheckNuAuthTx(tx, pindexPrev, state);
    case TRANSACTION_NUANCE_REVOKE:
        return CheckNuRevAuthTx(tx, pindexPrev, state);
    case TRANSACTION_NUANCE_CHECKPOINT:
        return CheckNuCheckTx(tx, pindexPrev, state);
    case TRANSACTION_NUANCE_TRANSFER:
        return CheckNuXferTx(tx, pindexPrev, state);
    case TRANSACTION_MCP_REGISTER:
        return CheckMcpRegTx(tx, pindexPrev, state);
    case TRANSACTION_MCP_UNREGISTER:
        return CheckMcpUnregTx(tx, pindexPrev, state);
    case TRANSACTION_MCP_AUTHORIZE:
        return CheckMcpAuthTx(tx, pindexPrev, state);
    case TRANSACTION_MCP_REVOKE:
        return CheckMcpRevAuthTx(tx, pindexPrev, state);
    case TRANSACTION_MCP_CHECK:
        return CheckMcpCheckTx(tx, pindexPrev, state);
    case TRANSACTION_MCP_TRANSFER:
        return CheckMcpXferTx(tx, pindexPrev, state);

    }

    return state.DoS(10, false, REJECT_INVALID, "bad-tx-type-check");
}

bool ProcessSpecialTx(const CTransaction& tx, const CBlockIndex* pindex, CValidationState& state)
{
    if (tx.nVersion != 3 || tx.nType == TRANSACTION_NORMAL) {
        return true;
    }

    switch (tx.nType) {
    case TRANSACTION_PROVIDER_REGISTER:
    case TRANSACTION_PROVIDER_UPDATE_SERVICE:
    case TRANSACTION_PROVIDER_UPDATE_REGISTRAR:
    case TRANSACTION_PROVIDER_UPDATE_REVOKE:
        return true; // handled in batches per block
    case TRANSACTION_COINBASE:
        return true; // nothing to do
    case TRANSACTION_QUORUM_COMMITMENT:
        return true; // handled per block
    case TRANSACTION_CONCEPT_REGISTER:
    case TRANSACTION_CONCEPT_UNREGISTER:
    case TRANSACTION_CONCEPT_AUTHORIZE:
    case TRANSACTION_CONCEPT_REVOKE:
    case TRANSACTION_CONCEPT_UPDATE:
    case TRANSACTION_CONCEPT_TRANSFER:
        return true; // concepts active
    case TRANSACTION_NUANCE_REGISTER:
    case TRANSACTION_NUANCE_UNREGISTER:
    case TRANSACTION_NUANCE_AUTHORIZE:
    case TRANSACTION_NUANCE_REVOKE:
    case TRANSACTION_NUANCE_CHECKPOINT:
    case TRANSACTION_NUANCE_TRANSFER:
        return true; // nuances active
    case TRANSACTION_MCP_REGISTER:
    case TRANSACTION_MCP_UNREGISTER:
    case TRANSACTION_MCP_AUTHORIZE:
    case TRANSACTION_MCP_REVOKE:
    case TRANSACTION_MCP_CHECK:
    case TRANSACTION_MCP_TRANSFER:
        return true; // concepts active
    }

    return state.DoS(100, false, REJECT_INVALID, "bad-tx-type-proc");
}

bool UndoSpecialTx(const CTransaction& tx, const CBlockIndex* pindex)
{
    if (tx.nVersion != 3 || tx.nType == TRANSACTION_NORMAL) {
        return true;
    }

    switch (tx.nType) {
    case TRANSACTION_PROVIDER_REGISTER:
    case TRANSACTION_PROVIDER_UPDATE_SERVICE:
    case TRANSACTION_PROVIDER_UPDATE_REGISTRAR:
    case TRANSACTION_PROVIDER_UPDATE_REVOKE:
        return true; // handled in batches per block
    case TRANSACTION_COINBASE:
        return true; // nothing to do
    case TRANSACTION_QUORUM_COMMITMENT:
        return true; // handled per block
    case TRANSACTION_CONCEPT_REGISTER:
    case TRANSACTION_CONCEPT_UNREGISTER:
    case TRANSACTION_CONCEPT_AUTHORIZE:
    case TRANSACTION_CONCEPT_REVOKE:
    case TRANSACTION_CONCEPT_UPDATE:
    case TRANSACTION_CONCEPT_TRANSFER:
        return true; // concepts active
    case TRANSACTION_NUANCE_REGISTER:
    case TRANSACTION_NUANCE_UNREGISTER:
    case TRANSACTION_NUANCE_AUTHORIZE:
    case TRANSACTION_NUANCE_REVOKE:
    case TRANSACTION_NUANCE_CHECKPOINT:
    case TRANSACTION_NUANCE_TRANSFER:
        return true; // nuances active
    case TRANSACTION_MCP_REGISTER:
    case TRANSACTION_MCP_UNREGISTER:
    case TRANSACTION_MCP_AUTHORIZE:
    case TRANSACTION_MCP_REVOKE:
    case TRANSACTION_MCP_CHECK:
    case TRANSACTION_MCP_TRANSFER:
        return true; // mcp active
    }

    return false;
}

bool ProcessSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, CValidationState& state)
{
    for (int i = 0; i < (int)block.vtx.size(); i++) {
        const CTransaction& tx = *block.vtx[i];
        if (!CheckSpecialTx(tx, pindex->pprev, state)) {
            return false;
        }
        if (!ProcessSpecialTx(tx, pindex, state)) {
            return false;
        }
    }

    if (!llmq::quorumBlockProcessor->ProcessBlock(block, pindex, state)) {
        return false;
    }

    if (!deterministicMNManager->ProcessBlock(block, pindex, state)) {
        return false;
    }

    if (!CheckCbTxMerkleRootMNList(block, pindex, state)) {
        return false;
    }

    return true;
}

bool UndoSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex)
{
    for (int i = (int)block.vtx.size() - 1; i >= 0; --i) {
        const CTransaction& tx = *block.vtx[i];
        if (!UndoSpecialTx(tx, pindex)) {
            return false;
        }
    }

    if (!deterministicMNManager->UndoBlock(block, pindex)) {
        return false;
    }

    if (!llmq::quorumBlockProcessor->UndoBlock(block, pindex)) {
        return false;
    }

    return true;
}

uint256 CalcTxInputsHash(const CTransaction& tx)
{
    CHashWriter hw(CLIENT_VERSION, SER_GETHASH);
    for (const auto& in : tx.vin) {
        hw << in.prevout;
    }
    return hw.GetHash();
}
