// Known answers against public eCash betanet data (slot 2): every block fetched from the
// public seed peer, the enforcer's BMM/deposit data, and the seed index.
#include "test.h"

#include <bitnames/fixture.h>

#include <cstdio>
#include <set>

using namespace bitnames;

static const fixture::Data& data()
{
    static std::optional<fixture::Data> d;
    if (!d) {
        std::string err;
        d = fixture::load(bttest::data_dir() + "/betanet", err);
        if (!d) std::fprintf(stderr, "fixture load: %s\n", err.c_str());
    }
    return *d;
}

TEST(betanet_blocks_codec_and_hashes)
{
    // M1: bincode decode -> re-encode identical; header hash == the index's id; the index's
    // merkle root; header chain linked from genesis.
    auto& d = data();
    REQUIRE(d.blocks.size() >= 2209);
    std::optional<Hash32> prev;
    uint32_t exact = 0, index_ids = 0, index_roots = 0;
    for (auto& [h, raw] : d.blocks) {
        Block b = fixture::decode_block_response(raw);
        Writer w;
        w.u32(0);
        bincode(w, b.header);
        bincode(w, b.body);
        if (w.buf == raw) exact++;
        CHECK(b.header.prev_side_hash == prev);
        prev = b.header.hash();
        auto it = d.index.find(h);
        if (it != d.index.end() && h > 0) {
            if (it->second.id == *prev) index_ids++;
            if (it->second.merkle_root == b.header.merkle_root) index_roots++;
        }
    }
    std::fprintf(stderr, "  %zu blocks, %u byte-exact, %u ids and %u merkle roots equal the index (heights 1..%u)\n", d.blocks.size(), exact,
                 index_ids, index_roots, d.index.rbegin()->first);
    CHECK_EQ(exact, uint32_t(d.blocks.size()));
    CHECK_EQ(index_ids, d.index.rbegin()->first);
    CHECK_EQ(index_roots, d.index.rbegin()->first);
    // genesis BMM'd at mainchain 968,910, before the enforcer's reported activation 968,998
    auto& g = d.main_by_height.begin()->second;
    CHECK_EQ(g.header.height, 968910u);
    CHECK(g.info.bmm_commitment == fixture::decode_block_response(d.blocks[0].second).header.hash());
}

TEST(betanet_index_tx_hex_borsh)
{
    // every tx the seed index serves: borsh decode -> re-encode identical, blake3 == txid
    size_t n = 0;
    for (auto& [txid, hex] : data().txhex) {
        auto raw = bt::hex_decode(hex);
        REQUIRE(raw.has_value());
        Reader r(*raw);
        Transaction t = borsh_de_transaction(r);
        CHECK(r.empty());
        CHECK(t.canonical_bytes() == *raw);
        CHECK_EQ(bt::hex_encode(t.txid()), txid);
        Writer w;
        bincode(w, t);
        Reader br(w.buf);
        CHECK(de_transaction(br).canonical_bytes() == *raw);
        n++;
    }
    CHECK_EQ(n, size_t(151));
}

TEST(betanet_replay_all_checks)
{
    // M2: every block through prevalidate + connect with every check on, 2WPD windows from
    // the enforcer, state matches what the chain implies.
    bt::kv::MemStore store;
    State st;
    auto r = fixture::replay(data(), st, store);
    std::fprintf(stderr,
                 "  %u blocks connected, %u byte-exact, %u BMM verified, %u signatures, %u tx inclusions (%zu distinct txids, %u zero-input), "
                 "%u reservations, %u registrations, %u updates, %u deposits; %s\n",
                 r.blocks, r.reencoded_exact, r.bmm_verified, r.signatures, r.tx_inclusions, r.txid_counts.size(), r.zero_input_txs, r.reservations,
                 r.registrations, r.updates, r.deposits, r.error.c_str());
    CHECK(r.error.empty());
    CHECK_EQ(r.blocks, uint32_t(data().blocks.size()));
    CHECK_EQ(r.bmm_verified, r.blocks);
    // the index's numbers at height 2205: 1,081 inclusions of 151 distinct txids
    uint32_t incl_2205 = 0;
    std::set<Hash32> ids_2205;
    for (auto& [h, raw] : data().blocks) {
        if (h > 2205) break;
        for (auto& t : fixture::decode_block_response(raw).body.transactions) {
            incl_2205++;
            ids_2205.insert(t.txid());
        }
    }
    std::fprintf(stderr, "  up to height 2205: %u inclusions, %zu distinct txids\n", incl_2205, ids_2205.size());
    CHECK_EQ(incl_2205, 1081u);
    CHECK_EQ(ids_2205.size(), size_t(151));
    bt::kv::Txn t(store);
    size_t dep_events = 0;
    for (uint32_t h = 0; h <= *st.height(t); h++) dep_events += st.block_index_events(t, h).deposits.size();
    CHECK_EQ(dep_events, size_t(12)); // get_block_index deposits = the enforcer's 12 deposit events
    std::fprintf(stderr, "  tip height %u, %zu utxos, %zu stxos, %zu names, %zu open reservations, wealth %llu sats\n", *st.height(t), st.utxos(t).size(),
                 st.stxos(t).size(), st.bitnames(t).size(), st.reservations(t).size(), (unsigned long long)st.sidechain_wealth(t));
    for (auto& [name, rec] : st.bitnames(t))
        std::fprintf(stderr, "  name %s seq %s\n", bt::hex_encode(name).c_str(), seq_id_to_string(rec.seq_id).c_str());
}

TEST(betanet_rollback_and_reconnect)
{
    // Disconnect blocks newest first (2WPD window, then the block, as net_task.rs
    // disconnect_tip_ does) until the first block their node cannot disconnect either, then
    // reconnect everything and compare the state.
    bt::kv::MemStore store;
    State st;
    std::vector<fixture::ReplayStep> steps;
    auto r = fixture::replay(data(), st, store, &steps);
    REQUIRE(r.error.empty());
    auto snapshot = [&] {
        bt::kv::Txn t(store);
        std::string s;
        for (auto& [op, o] : st.utxos(t)) s += op.to_string() + ";";
        for (auto& [name, rec] : st.bitnames(t)) s += bt::hex_encode(name) + std::to_string(rec.seq_id) + ";";
        for (auto& [txid, c] : st.reservations(t)) s += bt::hex_encode(txid) + ";";
        return s + std::to_string(st.sidechain_wealth(t));
    };
    std::string tip_state = snapshot();
    size_t i = steps.size();
    std::string stop;
    while (i > 0) {
        bt::kv::Txn t(store);
        try {
            st.disconnect_2wpd(t, steps[i - 1].window);
            st.disconnect_tip(t, steps[i - 1].block.header, steps[i - 1].block.body);
        } catch (const StateError& e) {
            stop = e.what();
            break;
        }
        t.commit();
        i--;
    }
    std::fprintf(stderr, "  disconnected %zu blocks; stopped at height %zu: %s\n", steps.size() - i, i ? i - 1 : 0, stop.empty() ? "(genesis)" : stop.c_str());
    // reconnect the disconnected blocks with every check and compare
    for (size_t k = i; k < steps.size(); k++) {
        bt::kv::Txn t(store);
        auto pre = st.prevalidate(t, steps[k].block.header, steps[k].block.body);
        st.connect_prevalidated(t, steps[k].block.header, steps[k].block.body, pre);
        st.connect_2wpd(t, steps[k].window);
        t.commit();
    }
    CHECK(snapshot() == tip_state);
}

TEST(betanet_replay_census)
{
    // Where zero-input replays sit: blocks repeating a txid inside the block, and txids
    // confirmed in more than one block.
    std::map<Hash32, std::vector<uint32_t>> where;
    uint32_t intra = 0;
    for (auto& [h, raw] : data().blocks) {
        std::set<Hash32> seen;
        bool dup = false;
        for (auto& t : fixture::decode_block_response(raw).body.transactions) {
            auto id = t.txid();
            if (!seen.insert(id).second) dup = true;
            where[id].push_back(h);
        }
        if (dup) intra++;
    }
    uint32_t multi = 0;
    size_t maxn = 0;
    for (auto& [id, hs] : where) {
        std::set<uint32_t> blocks(hs.begin(), hs.end());
        if (blocks.size() > 1) multi++;
        maxn = std::max(maxn, hs.size());
    }
    auto f = where.find(*bt::hex_to_array<32>("f427eb6760c8b88638b93cd0353b170d0a1510b31bbcf5d82bab111009f22868"));
    std::fprintf(stderr, "  %u blocks repeat a txid inside the block; %u txids are in more than one block; most-repeated txid confirmed %zu times\n", intra,
                 multi, maxn);
    if (f != where.end()) {
        std::string hs;
        for (auto x : f->second) hs += std::to_string(x) + " ";
        std::fprintf(stderr, "  f427eb67... confirmed at heights %s\n", hs.c_str());
    }
    CHECK(multi > 0);
}

#include <bitnames/json.h>

TEST(betanet_registration_json_shapes)
{
    // The live registration 81bd13db... carries commitment + v4 34.24.210.169:6002 + an
    // encryption key + a signing key (study §2); check the serde_json forms we serve.
    bt::kv::MemStore store;
    State st;
    auto r = fixture::replay(data(), st, store);
    REQUIRE(r.error.empty());
    bt::kv::Txn t(store);
    bool found = false;
    for (auto& [name, rec] : st.bitnames(t)) {
        auto d = rec.current();
        if (!d.data.socket_addr_v4) continue;
        UniValue j = json::bitname_data(d);
        std::fprintf(stderr, "  %s\n", j.write().c_str());
        CHECK_EQ(j["socket_addr_v4"].get_str(), std::string("34.24.210.169:6002"));
        CHECK(j["commitment"].isArray() && j["commitment"].size() == 32);
        CHECK(j["encryption_pubkey"].get_str().rfind("bn-enc1", 0) == 0);
        CHECK(j["signing_pubkey"].get_str().rfind("bn-svk1", 0) == 0);
        CHECK(vk_from_string(j["signing_pubkey"].get_str()) == d.data.signing_pubkey);
        CHECK(epk_from_string(j["encryption_pubkey"].get_str()) == d.data.encryption_pubkey);
        CHECK(seq_id_from_string(j["seq_id"].get_str()) == std::optional<uint32_t>(d.seq_id));
        found = true;
    }
    CHECK(found);
    // the first registration ever has seq 0 = "1739-0029" (study §2)
    CHECK_EQ(seq_id_to_string(0), std::string("1739-0029"));
}
