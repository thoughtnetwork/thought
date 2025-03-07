// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2021 Thought Networks, LLC
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include "arith_uint256.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateDevNetGenesisBlock(const uint256 &prevBlockHash, const std::string& devNetName, uint32_t nTime, uint32_t nNonce, uint32_t nBits, const CAmount& genesisReward)
{
    assert(!devNetName.empty());

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    // put height (BIP34) and devnet name into coinbase
    txNew.vin[0].scriptSig = CScript() << 1 << std::vector<unsigned char>(devNetName.begin(), devNetName.end());
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = CScript() << OP_RETURN;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = 4;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock = prevBlockHash;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
 *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
 *   vMerkleTree: e0028e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "USA Today 14/Mar/2018 Hawking's death, Einstein's birth, and Pi Day: what does it all mean?";
    const CScript genesisOutputScript = CScript() << ParseHex("04ed28f11f74795344edfdbc1fccb1e6de37c909ab0c2a535aa6a054fca6fd34b05e3ed9822fa00df98698555d7582777afbc355ece13b7a47004ffe58c0b66c08") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

static CBlock FindDevNetGenesisBlock(const Consensus::Params& params, const CBlock &prevBlock, const CAmount& reward)
{
    std::string devNetName = GetDevNetName();
    assert(!devNetName.empty());

    CBlock block = CreateDevNetGenesisBlock(prevBlock.GetHash(), devNetName.c_str(), prevBlock.nTime + 1, 0, prevBlock.nBits, reward);

    arith_uint256 bnTarget;
    bnTarget.SetCompact(block.nBits);

    for (uint32_t nNonce = 0; nNonce < UINT32_MAX; nNonce++) {
        block.nNonce = nNonce;

        uint256 hash = block.GetHash();
        if (UintToArith256(hash) <= bnTarget)
            return block;
    }

    // This is very unlikely to happen as we start the devnet with a very low difficulty. In many cases even the first
    // iteration of the above loop will give a result already
    error("FindDevNetGenesisBlock: could not find devnet genesis block for %s", devNetName);
    assert(false);
}

// this one is for testing only
static Consensus::LLMQParams llmq10_60 = {
        .type = Consensus::LLMQ_10_60,
        .name = "llmq_10",
        .size = 10,
        .minSize = 6,
        .threshold = 6,

        .dkgInterval = 24, // one DKG per hour
        .dkgPhaseBlocks = 2,
        .dkgMiningWindowStart = 10, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 18,
};

static Consensus::LLMQParams llmq50_60 = {
        .type = Consensus::LLMQ_50_60,
        .name = "llmq_50_60",
        .size = 50,
        .minSize = 40,
        .threshold = 30,

        .dkgInterval = 24, // one DKG per hour
        .dkgPhaseBlocks = 2,
        .dkgMiningWindowStart = 10, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 18,
};

static Consensus::LLMQParams llmq400_60 = {
        .type = Consensus::LLMQ_400_60,
        .name = "llmq_400_51",
        .size = 400,
        .minSize = 300,
        .threshold = 240,

        .dkgInterval = 24 * 12, // one DKG every 12 hours
        .dkgPhaseBlocks = 4,
        .dkgMiningWindowStart = 20, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 28,
};

// Used for deployment and min-proto-version signalling, so it needs a higher threshold
static Consensus::LLMQParams llmq400_85 = {
        .type = Consensus::LLMQ_400_85,
        .name = "llmq_400_85",
        .size = 400,
        .minSize = 350,
        .threshold = 340,

        .dkgInterval = 24 * 24, // one DKG every 24 hours
        .dkgPhaseBlocks = 4,
        .dkgMiningWindowStart = 20, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 48, // give it a larger mining window to make sure it is mined
};


/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */


class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 1299382; // Note: actual number of blocks per calendar year with DGW v3 is ~200700 (for example 449750 - 249050)
        consensus.nMasternodePaymentsStartBlock = 385627; // 5/29/2019, not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 439027; // actual historical value
        consensus.nMasternodePaymentsIncreasePeriod = 890*60; // 17280 - actual historical value, increase every 2 months
        consensus.nInstantSendConfirmationsRequired = 6;
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 385627; // actual historical value
        consensus.nBudgetPaymentsCycleBlocks = 26700; // ~(60*24*30)/1.618, actual number of blocks per month is 324846 / 12 = 27070
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nSuperblockStartBlock = 20000000; // Approx never
        consensus.nSuperblockStartHash = uint256S("0052548ec1345c8769322d9298297cefd5aa65504a02619a128bfb62d11d89f9"); // update this
        consensus.nSuperblockCycle = 26700; // ~(60*24*30)/1.618, actual number of blocks per month is 324846 / 12 = 27070
        consensus.nGovernanceMinQuorum = 40;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 15;
	      consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("000000008adb723e6f7a16be978cac979c2173b67752afc6d2a3f80110fe6c72");
        consensus.BIP65Height = 0; // 00000000000076d8fcea02ec0963de4abfd01e771fec0863f960c2c64fe6f357
        consensus.BIP66Height = 0; // 00000000000b1fa2dfa312863570e13fae9ca7b5566cb27e55422620b469aefa
        consensus.DIP0001Height = 385627;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20
        consensus.cuckooPowLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.cuckooGraphSize = 24;
        consensus.nPowTargetTimespan = 1.618 * 24 * 60 * 60; // Thought: 1 day
        consensus.nPowTargetSpacing = 1.618 * 60; // Thought: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nPowKGWHeight = 15200; //disabled in POW
        consensus.nPowDGWHeight = 642605; // approximately Mar 14,2020
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1558877442; // May 26th, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1564427763; // July 29th, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nThreshold = 2; // force CSV

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 1558877442; // Dec 13th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 1564427763; // Dec 13th, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThreshold = 2; // force DIP001, 50% of 100

        // Deployment of BIP147
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = 1558877442; // Dec 13th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = 1564427763; // Dec 13th, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nThreshold = 2; // force BIP147, 50% of 100

        // Deployment of DIP0003
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = 1592092800; // Jun 14th, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = 1623628800; // Jun 14th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nWindowSize = 200;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nThreshold = 20; // 10% of 200

	// Implementation of MIDAS
        consensus.midasStartHeight = 1;
        consensus.midasValidHeight = 512;


        consensus.CuckooHardForkBlockHeight = 246500;
        consensus.CuckooRequiredBlockHeight = 248800;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000009f11cd8f3c0a6"); // 1314126

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000f6c1b2cf55842736830bb3586f6171959f2d79f300e1a2cbd7ef943f869"); // 1314126

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x59;
        pchMessageStart[1] = 0x47;
        pchMessageStart[2] = 0x2e;
        pchMessageStart[3] = 0xe4;
        vAlertPubKey = ParseHex("0436bb00757a032e37da93536115b10f0f69ee322b38b1b27cb4d46236f1e126598cc6a89030ec1bd1b417743462f59802bbb83beb7ce2b46743b1a4287acb2daa");
        nDefaultPort = 10618;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1521039602, 2074325340, 0x1d00ffff, 1, 1618 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.genesisBlockTime = genesis.GetBlockTime();
        assert(consensus.hashGenesisBlock == uint256S("0x00000000917e049641189c33d6b1275155e89b7b498b3b4f16d488f60afe513b"));
        assert(genesis.hashMerkleRoot == uint256S("0x483a98bfa350f319e52eceaa79585fab8e5ac49c6235f720915e9c671a03c2d6"));

        vSeeds.push_back(CDNSSeedData("phee.thought.live", "phee.thought.live"));
        vSeeds.push_back(CDNSSeedData("phi.thought.live", "phi.thought.live"));
        vSeeds.push_back(CDNSSeedData("pho.thought.live", "pho.thought.live"));
        vSeeds.push_back(CDNSSeedData("phum.thought.live", "phum.thought.live"));

        // Thought addresses start with 'X'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,7);
        // Thought script addresses start with '7'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,9);
        // Thought private keys start with '7' or 'X'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,123);
        // Thought BIP32 pubkeys start with 'xpub' (Thought defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0xFb)(0xC6)(0xA0)(0x0D).convert_to_container<std::vector<unsigned char> >();
        // Thought BIP32 prvkeys start with 'xprv' (Thought defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x5A)(0xEB)(0xD8)(0xC6).convert_to_container<std::vector<unsigned char> >();

        // Thought BIP44 coin type is '5'
        nExtCoinType = 5;

        // vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_50_60] = llmq50_60;
        consensus.llmqs[Consensus::LLMQ_400_60] = llmq400_60;
        consensus.llmqs[Consensus::LLMQ_400_85] = llmq400_85;

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fRequireRoutableExternalIP = true;
        fMineBlocksOnDemand = false;
        fAllowMultipleAddressesFromGroup = false;
        fAllowMultiplePorts = false;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour

        vSporkAddresses = {"3vjBVUDb38RDsByGVFZ3AVkzB4eU1XJ9ox"};
        nMinSporkKeys = 1;
        fBIP9CheckMasternodesUpgraded = true;
        consensus.fLLMQAllowDummyCommitments = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("00000000917e049641189c33d6b1275155e89b7b498b3b4f16d488f60afe513b"))
            ( 2, uint256S("00000000c4c1989f0979bae2b24840b48ddb5197866a8ee99c9399a2512ec588"))
            ( 5, uint256S("000000003a062431a6e4430a6ade4ab402a29165462491338c98b336a8afb6ab"))
            ( 256, uint256S("00000000acf5b9f9eb1ea8c56f07ff00c2e3b5335c1b574f98cc3b8b55b70ec3"))
            ( 1024, uint256S("000000006aef3c0953d44120c972061811aca7a59167076573f9063e46265419"))
            ( 43010, uint256S("00000000328f2e44914cf6af972de811d0f4869f9b4e9217e4093dd297c79f49"))
            ( 229731, uint256S("000000006645878b6aa7c4f10044b9914e994f11e1c3905c72b7f7612c417a94"))
            ( 248000, uint256S("006b52a5d017eb2590d25750c46542b2de43f7a3fdc6394d95db458cbcb35f85"))
            ( 388285, uint256S("00e0d38562e2f576c3c501f4768b282824a7f9489778537c49e3b5492923f5c5"))
            ( 500000, uint256S("0052548ec1345c8769322d9298297cefd5aa65504a02619a128bfb62d11d89f9"))
            ( 615460, uint256S("0074d0258d568298cbd1e6a2a12e0076059bcd4e55eeab9c5ad41989a4d3e5de"))
            ( 933662, uint256S("0033fcb9b3caa3271705c610afdf544684d28e6b975a3b97be3b05ad3a5eaaf4"))
            ( 1036062, uint256S("000da1b7f88d5571c8b17d598c6f38df90e2e8b44a426950166c0eea3bad02b2"))
            ( 1138462, uint256S("00008a3a2328e2b7143ef1862312e69ccab7907ab26365b673f23c186d3c60cc"))
            ( 1314126, uint256S("00000f6c1b2cf55842736830bb3586f6171959f2d79f300e1a2cbd7ef943f869"))
            ( 1647955, uint256S("0000279c4f19d8922d7e99d51be6e4d7586000817d81bee4231713fce9f23db3"))
        };

        chainTxData = ChainTxData{
            1611605424, // * UNIX timestamp of last known number of transactions
            938246,    // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            1         // * estimated number of transactions per second after that timestamp
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 1299382;
        consensus.nMasternodePaymentsStartBlock = 153668; // 05/29/2019, not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 154668;
        consensus.nMasternodePaymentsIncreasePeriod = 100;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 4100;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 4200; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPeymentsStartBlock
        consensus.nSuperblockStartHash = uint256(); // do not check this on testnet
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on testnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
	      consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("000000007459c5f4deaaa14268bb8e6989461227ba743509de6ce194bad621c7");
        consensus.BIP65Height = 0; // 0000039cf01242c7f921dcb4806a5994bc003b48c1973ae0c89b67809c2bb2ab
        consensus.BIP66Height = 0; // 0000002acdd29a14583540cb72e1c5cc83783560e38fa7081495d474fe1671f7
        consensus.DIP0001Height = 0;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20
        consensus.cuckooPowLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.cuckooGraphSize = 24;
        consensus.nPowTargetTimespan = 1.618 * 24 * 60 * 60; // Thought: 1 day
        consensus.nPowTargetSpacing = 1.618 * 60; // Thought: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nPowKGWHeight = 4002; // disabled in POW
        consensus.nPowDGWHeight = 208000; // Nov 15th 2019
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1558877442; // May 26th, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1564427763; // July 29th, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nThreshold = 2; // force CSV

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 1558877442; // Dec 13th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 1564427763; // Dec 13th, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThreshold = 2; // force DIP001, 50% of 100

        // Deployment of BIP147
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = 1558877442; // Dec 13th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = 1564427763; // Dec 13th, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nThreshold = 2; // force BIP147, 50% of 100

        // Deployment of DIP0003
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = 1546300800; // Jan 1st, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = 1577836800; // Jan 1st, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nThreshold = 2; // 50% of 100

        // Implementation of MIDAS
        consensus.midasStartHeight = 2;
        consensus.midasValidHeight = 2;

        // Block to hard fork to Cuckoo Cycle POW
        consensus.CuckooHardForkBlockHeight = 44;
        consensus.CuckooRequiredBlockHeight = 100;


        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000002c071d46b3"); // 453224

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x004ca72e4195eff0fd071142c6ec8988f3436071d13c26e1ece0ca232a74dc18"); // 453224

        pchMessageStart[0] = 0x2b;
        pchMessageStart[1] = 0x99;
        pchMessageStart[2] = 0x39;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("046db944e7b455866d343fa5c64f2efc0bbcdf1ea16ac092df003e5dafb58009440204cd7f234a20c70ccb0fedf384342d6a0e94adf875f27e934344c4b2906b3d");
        nDefaultPort = 11618;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1521039602, 2074325340, 0x1d00ffff, 1, 1618 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.genesisBlockTime = genesis.GetBlockTime();
        assert(consensus.hashGenesisBlock == uint256S("00000000917e049641189c33d6b1275155e89b7b498b3b4f16d488f60afe513b"));
        assert(genesis.hashMerkleRoot == uint256S("483a98bfa350f319e52eceaa79585fab8e5ac49c6235f720915e9c671a03c2d6"));

        vFixedSeeds.clear();
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("testnet.phee.thought.live", "testnet.phee.thought.live"));
  //      vSeeds.push_back(CDNSSeedData("masternode.io", "test.dnsseed.masternode.io"));

        // Testnet Thought addresses start with 'y'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,109);
        // Testnet Thought script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,193);
        // Testnet private keys start with '9' or 'c' (Thought defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,235);
        // Testnet Thought BIP32 pubkeys start with 'tpub' (Thought defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x5D)(0x40)(0x5F)(0x7A).convert_to_container<std::vector<unsigned char> >();
        // Testnet Thought BIP32 prvkeys start with 'tprv' (Thought defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0xB6)(0xF1)(0x3F)(0x50).convert_to_container<std::vector<unsigned char> >();

        // Testnet Thought BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_50_60] = llmq50_60;
        consensus.llmqs[Consensus::LLMQ_400_60] = llmq400_60;
        consensus.llmqs[Consensus::LLMQ_400_85] = llmq400_85;

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fRequireRoutableExternalIP = true;
        fMineBlocksOnDemand = false;
        fAllowMultipleAddressesFromGroup = false;
        fAllowMultiplePorts = false;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        vSporkAddresses = {"kxkf3ojUeHpzBuU5qdXEWKND5E4LmkQ6qU"};
        nMinSporkKeys = 1;
        fBIP9CheckMasternodesUpgraded = true;
        consensus.fLLMQAllowDummyCommitments = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("0x00000000917e049641189c33d6b1275155e89b7b498b3b4f16d488f60afe513b"))
            ( 128, uint256S("0x000b288b55c8f6c919369ee26f517861f6552c294b7d262339c80de906fe01c8"))
            ( 154509, uint256S("0x001ecb9553a2d270c7055fee8b91401ac63f6c5f8e8926d958d88b679d8ccb70"))
            ( 203853, uint256S("0x0080d0bf98c3780b426892ba549c89abcd7c3c12812287888b087c5d759ddd42"))
            ( 206391, uint256S("0x00b4035a037a5522141b8be953ddf0382cdbd2e065e7fcaf7ff64eaf2963e9bb"))
            ( 351394, uint256S("0x0020e6e0d2d0292a4456ae92f0b846113d68194e0ba77dfec3c51f67a976d6e2"))
            ( 453224, uint256S("0x004ca72e4195eff0fd071142c6ec8988f3436071d13c26e1ece0ca232a74dc18"))
                  };

        chainTxData = ChainTxData{
            1611605222, // * UNIX timestamp of last known number of transactions
            351394,       // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.01        // * estimated number of transactions per second after that timestamp
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Devnet
 */
class CDevNetParams : public CChainParams {
public:
    CDevNetParams() {
        strNetworkID = "dev";
        consensus.nSubsidyHalvingInterval = 210240;
        consensus.nMasternodePaymentsStartBlock = 4010; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 4030;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 4100;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 4200; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPeymentsStartBlock
        consensus.nSuperblockStartHash = uint256(); // do not check this on devnet
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on devnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = 1; // BIP34 activated immediately on devnet
        consensus.BIP65Height = 1; // BIP65 activated immediately on devnet
        consensus.BIP66Height = 1; // BIP66 activated immediately on devnet
        consensus.DIP0001Height = 2; // DIP0001 activated immediately on devnet
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 1
        consensus.cuckooPowLimit = uint256S("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.cuckooGraphSize = 24;
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Thought: 1 day
        consensus.nPowTargetSpacing = 1.618 * 60; // Thought: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nPowKGWHeight = 1; // nPowKGWHeight >= nPowDGWHeight means "no KGW"
        consensus.nPowDGWHeight = 1;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 2398377599; // Dec 31st, 2045

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1506556800; // September 28th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 2398377599; // Dec 31st, 2045

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 1505692800; // Sep 18th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 2398377599; // Dec 31st, 2045
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThreshold = 50; // 50% of 100

        // Deployment of BIP147
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = 1517792400; // Feb 5th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = 2398377599; // Dec 31st, 2045
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nThreshold = 50; // 50% of 100

        // Deployment of DIP0003
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = 1535752800; // Sep 1st, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = 2398377599; // Dec 31st, 2045
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nThreshold = 2; // 50% of 100

        consensus.CuckooHardForkBlockHeight = 3000;
        consensus.CuckooRequiredBlockHeight = 3000;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000000000000000000000000000000000000000000000000000000000000");

        pchMessageStart[0] = 0xe2;
        pchMessageStart[1] = 0xca;
        pchMessageStart[2] = 0xff;
        pchMessageStart[3] = 0xce;
        vAlertPubKey = ParseHex("04517d8a699cb43d3938d7b24faaff7cda448ca4ea267723ba614784de661949bf632d6304316b244646dea079735b9a6fc4af804efb4752075b9fe2245e14e412");
        nDefaultPort = 12618;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1521040440, 1, 0x207fffff, 1, 1618 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.genesisBlockTime = genesis.GetBlockTime();
        assert(consensus.hashGenesisBlock == uint256S("730ca19408f5a6f6123ecbcb95fe2c016f642f6855c7a10abb1869fed657de3a"));
        assert(genesis.hashMerkleRoot == uint256S("483a98bfa350f319e52eceaa79585fab8e5ac49c6235f720915e9c671a03c2d6"));

        devnetGenesis = FindDevNetGenesisBlock(consensus, genesis, 809016994 * COIN);
        consensus.hashDevnetGenesisBlock = devnetGenesis.GetHash();

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("thoughtevo.org",  "devnet-seed.thoughtevo.org"));

        // Testnet Thought addresses start with 'y'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);
        // Testnet Thought script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        // Testnet private keys start with '9' or 'c' (Thought defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Testnet Thought BIP32 pubkeys start with 'tpub' (Thought defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet Thought BIP32 prvkeys start with 'tprv' (Thought defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        // Testnet Thought BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_50_60] = llmq50_60;
        consensus.llmqs[Consensus::LLMQ_400_60] = llmq400_60;
        consensus.llmqs[Consensus::LLMQ_400_85] = llmq400_85;

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fAllowMultipleAddressesFromGroup = true;
        fAllowMultiplePorts = true;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        vSporkAddresses = {"yXxY2HrDz8gELC4rRq1GRiXwB5KWdzJnAp"};
        nMinSporkKeys = 1;
        // devnets are started with no blocks and no MN, so we can't check for upgraded MN (as there are none)
        fBIP9CheckMasternodesUpgraded = false;
        consensus.fLLMQAllowDummyCommitments = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (      0, uint256S("0x730ca19408f5a6f6123ecbcb95fe2c016f642f6855c7a10abb1869fed657de3a"))
            (      1, devnetGenesis.GetHash())
        };

        chainTxData = ChainTxData{
            devnetGenesis.GetBlockTime(), // * UNIX timestamp of devnet genesis block
            2,                            // * we only have 2 coinbase transactions when a devnet is started up
            0.01                          // * estimated number of transactions per second
        };
    }

    void UpdateSubsidyAndDiffParams(int nMinimumDifficultyBlocks, int nHighSubsidyBlocks, int nHighSubsidyFactor)
    {
        consensus.nMinimumDifficultyBlocks = nMinimumDifficultyBlocks;
        consensus.nHighSubsidyBlocks = nHighSubsidyBlocks;
        consensus.nHighSubsidyFactor = nHighSubsidyFactor;
    }
};
static CDevNetParams *devNetParams;


/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMasternodePaymentsStartBlock = 240;
        consensus.nMasternodePaymentsIncreaseBlock = 350;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 1000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 1500;
        consensus.nSuperblockStartHash = uint256(); // do not check this on regtest
        consensus.nSuperblockCycle = 10;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 100;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.DIP0001Height = 2000;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 1
        consensus.cuckooPowLimit = uint256S("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.cuckooGraphSize = 24;
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Thought: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60; // Thought: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nPowKGWHeight = 15200; // same as mainnet
        consensus.nPowDGWHeight = 34140; // same as mainnet
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = 999999999999ULL;

        // Implementation of MIDAS
        consensus.midasStartHeight = 2;
        consensus.midasValidHeight = 2;

        // Block to hard fork to Cuckoo Cycle POW
        consensus.CuckooHardForkBlockHeight = 2010;
        consensus.CuckooRequiredBlockHeight = 2010;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xdc;
        nDefaultPort = 18618;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1512658235, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        consensus.genesisBlockTime = genesis.GetBlockTime();
        assert(consensus.hashGenesisBlock == uint256S("0x194774991708d488f09a88b155318372e5678af9445696e66525fa91b8cb0c28"));
        assert(genesis.hashMerkleRoot == uint256S("0xec791f82cd7f1d479c1b67209e76dc89ff851f422f17be8491d60ba2c23ec546"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fRequireRoutableExternalIP = false;
        fMineBlocksOnDemand = true;
        fAllowMultipleAddressesFromGroup = true;
        fAllowMultiplePorts = true;

        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        // privKey: cVcFUUr8Mrv8wM5V6CF38gXr6vMbVFPEWa3vA2fJLdbY53xM76tb
        vSporkAddresses = {"ydYbzXGsYFQvnxY5cEzVVaUhwZfEVVTVis"};
        nMinSporkKeys = 1;
        // regtest usually has no masternodes in most tests, so don't check for upgraged MNs
        fBIP9CheckMasternodesUpgraded = false;
        consensus.fLLMQAllowDummyCommitments = true;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x194774991708d488f09a88b155318372e5678af9445696e66525fa91b8cb0c28"))
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        // Regtest Thought addresses start with 'y'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);
        // Regtest Thought script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        // Regtest private keys start with '9' or 'c' (Thought defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Regtest Thought BIP32 pubkeys start with 'tpub' (Thought defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Regtest Thought BIP32 prvkeys start with 'tprv' (Thought defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        // Regtest Thought BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_10_60] = llmq10_60;
        consensus.llmqs[Consensus::LLMQ_50_60] = llmq50_60;
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }

    void UpdateBudgetParameters(int nMasternodePaymentsStartBlock, int nBudgetPaymentsStartBlock, int nSuperblockStartBlock)
    {
        consensus.nMasternodePaymentsStartBlock = nMasternodePaymentsStartBlock;
        consensus.nBudgetPaymentsStartBlock = nBudgetPaymentsStartBlock;
        consensus.nSuperblockStartBlock = nSuperblockStartBlock;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::DEVNET) {
            assert(devNetParams);
            return *devNetParams;
    } else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    if (network == CBaseChainParams::DEVNET) {
        devNetParams = (CDevNetParams*)new uint8_t[sizeof(CDevNetParams)];
        memset(devNetParams, 0, sizeof(CDevNetParams));
        new (devNetParams) CDevNetParams();
    }

    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}

void UpdateRegtestBudgetParameters(int nMasternodePaymentsStartBlock, int nBudgetPaymentsStartBlock, int nSuperblockStartBlock)
{
    regTestParams.UpdateBudgetParameters(nMasternodePaymentsStartBlock, nBudgetPaymentsStartBlock, nSuperblockStartBlock);
}

void UpdateDevnetSubsidyAndDiffParams(int nMinimumDifficultyBlocks, int nHighSubsidyBlocks, int nHighSubsidyFactor)
{
    assert(devNetParams);
    devNetParams->UpdateSubsidyAndDiffParams(nMinimumDifficultyBlocks, nHighSubsidyBlocks, nHighSubsidyFactor);
}
