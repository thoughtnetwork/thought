// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2017-2021 Thought Networks, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef THOUGHT_PRIMITIVES_BLOCK_H
#define THOUGHT_PRIMITIVES_BLOCK_H

#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"

static const int32_t CUCKOO_HARDFORK_VERSION_MASK = 0x40000000UL;
static const int64_t CUCKOO_HARDFORK_MIN_TIME = 1528835939; // 12 Jun 2018

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint32_t cuckooProof[42];

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

  template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
    	if (!(s.GetType() & SER_GETHASH) || !isCuckooPow()) {
    				READWRITE(this->nVersion);
    				READWRITE(hashPrevBlock);
    				READWRITE(hashMerkleRoot);
    				READWRITE(nTime);
    				READWRITE(nBits);
    				READWRITE(nNonce);
    	}
    	if (isCuckooPow()) {
    	   for (int i=0; i<42; i++) {
    	       READWRITE(cuckooProof[i]);
    	   }
    	}
    }

void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        for (int i=0; i<42; i++) {
          cuckooProof[i] = 0;
        }
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    bool isCuckooPow() const
    {
      if ((nVersion & CUCKOO_HARDFORK_VERSION_MASK) == 0)
    			return false;

      if (nTime < CUCKOO_HARDFORK_MIN_TIME)
    			return false;

      return true;
    }
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
	for (int i=0; i<42; i++) {
          block.cuckooProof[i] = cuckooProof[i];
        }  
      return block;
    }

    std::string ToString() const;
};


/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // THOUGHT_PRIMITIVES_BLOCK_H
