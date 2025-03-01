// Copyright (c) 2018-2025 Thought Network Ltd
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef THOUGHT_EVO_CONCEPTTX_H
#define THOUGHT_EVO_CONCEPTTX_H

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

// Create/Register concept
class CConRegTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Concept Registration Fields
    CService ipAddress;
    std::vector<unsigned char> mcpId;
    uint16_t version;
    std::vector<unsigned char> name;
    std::vector<unsigned char> conceptId;
    uint256 conceptHash;
    std::vector<unsigned char> conceptParentId;
    std::vector<unsigned char> conceptVersion;
    std::vector<unsigned char> codeLocation;

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
        READWRITE(conceptHash);
        READWRITE(conceptParentId);
        READWRITE(conceptVersion);
        READWRITE(codeLocation);
    }

    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};



// Remove/Unregister concept 
class CConUnregTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

    enum {
        DELETE = 0,
        HIDE = 1
    };

public:
    // Concept un-register Fields
    std::vector<unsigned char> conceptId;
    std::vector<unsigned char> conceptVersion;
    uint16_t action{DELETE};

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(conceptId);
        READWRITE(conceptVersion);
        READWRITE(action);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};



// Authorize concept user
class CConAuthTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Concept user authorization Fields
    std::vector<unsigned char> conceptId;
    std::vector<unsigned char> conceptVersion;
    uint256 authorizeWallet;


public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(conceptId);
        READWRITE(conceptVersion);
        READWRITE(authorizeWallet);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};



// Revoke concept authorization
class CConRevAuthTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Concept revoke authorization Fields
    std::vector<unsigned char> conceptId;
    std::vector<unsigned char> conceptVersion;
    uint256 revokeWallet;


public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(conceptId);
        READWRITE(conceptVersion);
        READWRITE(revokeWallet);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};



// Update concept
class CConUpTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Concept Update Fields
    std::vector<unsigned char> conceptId;
    std::vector<unsigned char> conceptVersion;
    uint256 conceptHash;
    std::vector<unsigned char> codeLocation;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(conceptId);
        READWRITE(conceptVersion);
        READWRITE(conceptHash);
        READWRITE(codeLocation);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};



// Transfer concept ownership
class CConXferTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Concept transfer Fields
    std::vector<unsigned char> conceptId;
    std::vector<unsigned char> conceptVersion;
    uint256 toWallet;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(conceptId);
        READWRITE(conceptVersion);
        READWRITE(toWallet);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};

bool CheckConRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckConUpTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckConUnregTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckConXferTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckConAuthTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckConRevAuthTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);

#endif // THOUGHT_EVO_CONCEPTTX_H