// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <bitnames/fixture.h>

#include <univalue.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>

namespace bitnames::fixture {

using bt::mainchain::TwoWayPegData;

static std::string slurp(const std::string& p)
{
    std::ifstream f(p, std::ios::binary);
    std::ostringstream o;
    o << f.rdbuf();
    return o.str();
}

std::optional<Data> load(const std::string& dir, std::string& err)
{
    Data d;
    std::string all = slurp(dir + "/blocks.bin");
    size_t p = 0;
    while (p + 8 <= all.size()) {
        uint32_t h, n;
        std::memcpy(&h, all.data() + p, 4);
        std::memcpy(&n, all.data() + p + 4, 4);
        p += 8;
        if (p + n > all.size()) break;
        d.blocks.emplace_back(h, Bytes(all.begin() + p, all.begin() + p + n));
        p += n;
    }
    if (d.blocks.empty()) {
        err = "no blocks.bin";
        return std::nullopt;
    }
    {
        UniValue v;
        if (!v.read(slurp(dir + "/twpd2.json"))) {
            err = "bad twpd2.json";
            return std::nullopt;
        }
        for (auto& item : v["blocks"].getValues()) {
            auto hi = bt::mainchain::header_info_from_json(item["blockHeaderInfo"]);
            auto bi = bt::mainchain::block_info_from_json(item["blockInfo"]);
            if (!hi || !bi) {
                err = "bad twpd item";
                return std::nullopt;
            }
            d.main_by_height[hi->height] = MainBlock{*hi, *bi};
        }
    }
    {
        std::istringstream in(slurp(dir + "/index_blocks.jsonl"));
        std::string line;
        while (std::getline(in, line)) {
            UniValue v;
            if (line.empty() || !v.read(line)) continue;
            IndexBlock b;
            b.height = uint32_t(v["height"].getInt<int64_t>());
            b.id = *bt::hex_to_array<32>(v["id"].get_str());
            b.merkle_root = *bt::hex_to_array<32>(v["merkle_root"].get_str());
            b.tx_count = uint32_t(v["tx_count"].getInt<int64_t>());
            d.index[b.height] = b;
        }
    }
    {
        std::istringstream in(slurp(dir + "/txhex.jsonl"));
        std::string line;
        while (std::getline(in, line)) {
            UniValue v;
            if (line.empty() || !v.read(line)) continue;
            d.txhex[v["txid"].get_str()] = v["hex"].get_str();
        }
    }
    return d;
}

Block decode_block_response(ByteSpan raw)
{
    Reader r(raw);
    if (r.u32() != 0) throw bt::DecodeError("not a Block response");
    Block b;
    b.header = de_header(r);
    b.body = de_body(r);
    if (!r.empty()) throw bt::DecodeError("trailing bytes");
    return b;
}

ReplayResult replay(const Data& d, State& st, bt::kv::Store& store, std::vector<ReplayStep>* steps, uint32_t max_height)
{
    ReplayResult res;
    std::map<Hash32, uint32_t> bmm_at; // commitment -> mainchain height (first seen)
    for (auto& [h, mb] : d.main_by_height)
        if (mb.info.bmm_commitment) bmm_at.emplace(*mb.info.bmm_commitment, h);
    std::optional<uint32_t> prev_main_height;
    uint32_t expect = 0;
    for (auto& [height, raw] : d.blocks) {
        if (height > max_height) break;
        if (height != expect) {
            res.error = "non-contiguous blocks at " + std::to_string(height);
            return res;
        }
        expect++;
        Block b;
        try {
            b = decode_block_response(raw);
        } catch (const std::exception& e) {
            res.error = "decode at " + std::to_string(height) + ": " + e.what();
            return res;
        }
        Writer w;
        w.u32(0);
        bincode(w, b.header);
        bincode(w, b.body);
        if (w.buf == raw) res.reencoded_exact++;
        Hash32 id = b.header.hash();
        auto bh = bmm_at.find(id);
        if (bh == bmm_at.end()) {
            res.error = "no BMM commitment for height " + std::to_string(height);
            return res;
        }
        const MainBlock& bmm = d.main_by_height.at(bh->second);
        if (bmm.header.prev_block_hash != b.header.prev_main_hash) {
            res.error = "BMM block not a child of prev_main at " + std::to_string(height);
            return res;
        }
        res.bmm_verified++;
        uint32_t main_height = bh->second - 1;
        bt::kv::Txn txn(store);
        try {
            auto pre = st.prevalidate(txn, b.header, b.body);
            res.signatures += uint32_t(b.body.authorizations.size());
            for (auto& t : b.body.transactions) {
                res.tx_inclusions++;
                res.txid_counts[t.txid()]++;
                if (t.inputs.empty()) res.zero_input_txs++;
                if (t.is_reservation()) res.reservations++;
                if (t.is_registration()) res.registrations++;
                if (t.is_update()) res.updates++;
            }
            st.connect_prevalidated(txn, b.header, b.body, pre);
            TwoWayPegData win;
            for (auto& [h, mb] : d.main_by_height) {
                if (h > main_height) break;
                if (prev_main_height && h <= *prev_main_height) continue;
                if (mb.info.events.empty()) continue;
                for (auto& ev : mb.info.events)
                    if (std::holds_alternative<bt::mainchain::Deposit>(ev)) res.deposits++;
                win.block_info.emplace_back(mb.header.block_hash, mb.info);
            }
            st.connect_2wpd(txn, win);
            if (steps) steps->push_back(ReplayStep{b, win});
        } catch (const StateError& e) {
            res.error = "height " + std::to_string(height) + ": " + e.what();
            return res;
        }
        txn.commit();
        prev_main_height = main_height;
        res.blocks++;
    }
    return res;
}

} // namespace bitnames::fixture
