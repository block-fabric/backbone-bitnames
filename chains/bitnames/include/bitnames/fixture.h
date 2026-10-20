// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// Public eCash betanet data for BitNames (slot 2) and a replay through the state machine:
//   blocks.bin   every block 0..tip as fetched over P2P (bitnames-fetch-blocks)
//   twpd2.json   the public enforcer's GetTwoWayPegData for slot 2 (BMM + deposit events)
//   index_blocks.jsonl / txhex.jsonl  the seed index's block summaries and borsh tx hex
#pragma once

#include <bitnames/state.h>

#include <bt/kv.h>
#include <bt/mainchain.h>

#include <map>
#include <string>
#include <vector>

namespace bitnames::fixture {

struct MainBlock {
    bt::mainchain::BlockHeaderInfo header;
    bt::mainchain::BlockInfo info;
};

struct IndexBlock {
    uint32_t height = 0;
    Hash32 id, merkle_root;
    uint32_t tx_count = 0;
};

struct Data {
    std::vector<std::pair<uint32_t, Bytes>> blocks; // (height, bincode ResponseMessage::Block)
    std::map<uint32_t, MainBlock> main_by_height;
    std::map<uint32_t, IndexBlock> index;            // by height (the index's view)
    std::map<std::string, std::string> txhex;        // txid -> borsh hex
};

std::optional<Data> load(const std::string& dir, std::string& err);

struct ReplayStep {
    Block block;
    bt::mainchain::TwoWayPegData window;
};

struct ReplayResult {
    uint32_t blocks = 0;          // connected with every consensus check enabled
    uint32_t reencoded_exact = 0; // bincode re-encoding identical to the bytes received
    uint32_t bmm_verified = 0;    // commitment == header hash in a child of prev_main
    uint32_t signatures = 0;
    uint32_t tx_inclusions = 0;
    uint32_t zero_input_txs = 0;
    uint32_t deposits = 0;
    uint32_t reservations = 0, registrations = 0, updates = 0;
    std::map<Hash32, uint32_t> txid_counts;
    std::string error;
};

/** Replay with all checks (merkle, signatures, BMM against the enforcer data, 2WPD windows
 *  (prev_main(N-1), prev_main(N)], genesis window = all ancestors). */
ReplayResult replay(const Data& d, State& st, bt::kv::Store& store, std::vector<ReplayStep>* steps = nullptr,
                    uint32_t max_height = UINT32_MAX);

Block decode_block_response(ByteSpan raw);

} // namespace bitnames::fixture
