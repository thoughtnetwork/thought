// Copyright (c) 2018 The Dash Core developers
// Copyright (c) 2019 Thought Networks, LLC
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef THOUGHT_QUORUMS_INIT_H
#define THOUGHT_QUORUMS_INIT_H

class CEvoDB;

namespace llmq
{

void InitLLMQSystem(CEvoDB& evoDb);
void DestroyLLMQSystem();

}

#endif //THOUGHT_QUORUMS_INIT_H
