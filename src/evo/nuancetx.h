// Copyright (c) 2018-2025 Thought Network Ltd

// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef THOUGHT_EVO_NUANCETX_H
#define THOUGHT_EVO_NUANCETX_H

#include <bls/bls.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>

#include <netaddress.h>
#include <pubkey.h>
#include <univalue.h>

#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>         // streaming operators etc.
#include <boost/url/urls.hpp>

class CBlockIndex;
class CCoinsViewCache;

// Create/Register nuance
class CNuRegTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Nuance Registration Fields
    CService ipAddress;
    std::vector<unsigned char> mcpId; 
    uint16_t version;    
    std::vector<unsigned char> name; 
    std::vector<unsigned char> conceptId; 
    uint256 hash; 

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ipAddress);
        READWRITE(mcpId);
        READWRITE(version);
        READWRITE(name);
        READWRITE(conceptId);
        READWRITE(hash);
    }

    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};



// Remove/Unregister nuance
class CNuUnregTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

    enum {
        KILL = 0
    };

    enum {
        DELETE = 0,
        RETURN_TO_ORIGIN = 1,
        ARCHIVE = 2
    };

public:
    // Nuance Unregister Fields
    CService ipAddress;
    std::vector<unsigned char> mcpId;
    uint16_t version;
    std::vector<unsigned char> nuanceId;
    uint16_t action{KILL};
    uint16_t postAction{DELETE};

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ipAddress);
        READWRITE(mcpId);
        READWRITE(version);
        READWRITE(nuanceId);
        READWRITE(action);
        READWRITE(postAction);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};



// Authorize nuance user
class CNuAuthTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Nuance Authorization Fields
    CService ipAddress;
    std::vector<unsigned char> mcpId;
    uint16_t version;
    std::vector<unsigned char> nuanceId;
    uint256 authorizeWallet;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ipAddress);
        READWRITE(mcpId);
        READWRITE(version);
        READWRITE(nuanceId);
        READWRITE(authorizeWallet);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};



// Revoke authorization
class CNuRevAuthTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Nuance revoke authorization Fields
    CService ipAddress;
    std::vector<unsigned char> mcpId;
    uint16_t version;
    std::vector<unsigned char> nuanceId;
    uint256 revokeWallet;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ipAddress);
        READWRITE(mcpId);
        READWRITE(version);
        READWRITE(nuanceId);
        READWRITE(revokeWallet);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};



// Checkpoint nuance
class CNuCheckTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Nuance Checkpoint Fields
    CService ipAddress;
    std::vector<unsigned char> mcpId;
    uint16_t version;
    std::vector<unsigned char> nuanceId;
    uint256 hash;
    bool nuanceSatisfied;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ipAddress);
        READWRITE(mcpId);
        READWRITE(version);
        READWRITE(nuanceId);
        READWRITE(hash);
        READWRITE(nuanceSatisfied);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};



// Transfer nuance ownership
class CNuXferTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Nuance transfer Fields
    CService ipAddress;
    std::vector<unsigned char> mcpId;
    uint16_t version;
    std::vector<unsigned char> nuanceId;
    uint256 toWallet;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ipAddress);
        READWRITE(mcpId);
        READWRITE(version);
        READWRITE(nuanceId);
        READWRITE(toWallet);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};

bool CheckNuRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckNuUnregTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckNuXferTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckNuCheckTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckNuAuthTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckNuRevAuthTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);

#endif // THOUGHT_EVO_NUANCETX_H