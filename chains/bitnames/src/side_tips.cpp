// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <bitnames/side_tips.h>

#include <bt/log.h>

#include <deque>

namespace bitnames {

using bt::kv::Txn;

namespace {

Bytes unit_key() { return Bytes{0}; }

Bytes enc_info(const SideTipInfo& i)
{
    Writer w;
    w.u32(i.sidechain_height);
    w.raw(i.work.to_le());
    w.raw(i.main_block_hash);
    return w.buf;
}

SideTipInfo dec_info(ByteSpan v)
{
    Reader r(v);
    SideTipInfo i;
    i.sidechain_height = r.u32();
    i.work = U256::from_le(r.array<32>());
    i.main_block_hash = r.array<32>();
    return i;
}

std::string side_hex(const Hash32& h) { return bt::hex_encode(h); }
std::string main_hex(const Hash32& h) { return bt::hex_encode_rev(h.span()); }

/** their `MainchainTip::block_hash()`: all zeros when there is no tip. */
Hash32 tip_or_zero(const std::optional<Hash32>& h) { return h ? *h : Hash32{}; }

} // namespace

Bytes SideTips::ordered_key(const SideTipInfo& i)
{
    // bincode of SidechainTipInfo: [u8; 4] BE height, Work as serialize_bytes (u64 length 32,
    // then the BE bytes), BlockHash as serialize_bytes (length, internal bytes). The constant
    // length prefixes do not change the order, so they are left out.
    Writer w;
    w.u32be(i.sidechain_height);
    w.raw(i.work.to_be());
    w.raw(i.main_block_hash);
    return w.buf;
}

void SideTips::clear(Txn& t) const
{
    t.clear(T_MAIN_TIP);
    t.clear(T_TIPS);
    t.clear(T_ORDERED);
}

std::optional<Hash32> SideTips::mainchain_tip(const Txn& t) const
{
    auto v = t.get(T_MAIN_TIP, unit_key());
    if (!v || v->size() != 32) return std::nullopt;
    return Hash32::from_span(*v);
}

bool SideTips::contains(const Txn& t, const Hash32& side) const { return t.get(T_TIPS, side.span()).has_value(); }

std::optional<SideTipInfo> SideTips::info(const Txn& t, const Hash32& side) const
{
    auto v = t.get(T_TIPS, side.span());
    if (!v) return std::nullopt;
    return dec_info(*v);
}

std::optional<std::pair<Hash32, SideTipInfo>> SideTips::best(const Txn& t) const
{
    auto l = t.last(T_ORDERED);
    if (!l) return std::nullopt;
    Hash32 side = Hash32::from_span(l->second);
    auto i = info(t, side);
    if (!i) throw SideTipsError("ordered side tip without tip info " + side_hex(side));
    return std::make_pair(side, *i);
}

bool SideTips::in_ordered(const Txn& t, const Hash32& side) const
{
    auto i = info(t, side);
    return i && t.get(T_ORDERED, ordered_key(*i)).has_value();
}

// side_tips/mod.rs:194-235
void SideTips::connect_sidechain_tip(Txn& t, const Hash32& main, const U256& work, const Hash32& side,
                                     const std::optional<Hash32>& prev_side) const
{
    uint32_t height = 0;
    if (prev_side) {
        auto p = info(t, *prev_side);
        if (!p) throw SideTipsError("missing sidechain parent (" + side_hex(*prev_side) + ")");
        height = p->sidechain_height + 1; // saturating_add; u32::MAX is unreachable
    }
    if (contains(t, side)) return;
    SideTipInfo i{height, work, main};
    t.put(T_TIPS, side.span(), enc_info(i));
    t.put(T_ORDERED, ordered_key(i), side.span());
}

// side_tips/mod.rs:240-253
void SideTips::disconnect_sidechain_tip(Txn& t, const Hash32& side) const
{
    auto i = info(t, side);
    if (!i) return;
    t.del(T_ORDERED, ordered_key(*i));
    t.del(T_TIPS, side.span());
}

// side_tips/mod.rs:258-293
void SideTips::connect_mainchain_tip(Txn& t, const Archive& a, const Hash32& main,
                                     const std::optional<std::pair<Hash32, std::optional<Hash32>>>& commitment) const
{
    auto hi = a.need_main(t, main);
    auto cur = mainchain_tip(t);
    Hash32 expected = tip_or_zero(cur);
    if (hi.prev != expected)
        throw SideTipsError("failed to connect mainchain tip (" + main_hex(main) + "): invalid mainchain parent, expected (" + main_hex(expected) + ")");
    if (cur) {
        uint32_t th = a.need_main(t, *cur).height;
        if (hi.height != th + 1)
            throw SideTipsError("failed to connect mainchain tip (" + main_hex(main) + "): invalid mainchain tip height, expected (" + std::to_string(th + 1) + ")");
    }
    // their cumulative work, summed from the first mainchain block, is the archive's total work
    if (commitment) connect_sidechain_tip(t, main, hi.total_work, commitment->first, commitment->second);
    t.put(T_MAIN_TIP, unit_key(), main.span());
}

// side_tips/mod.rs:295-359. THE QUIRK: the committed sidechain block leaves only the ordered
// tips (and only when it was recorded at this main block); it stays in the tip set.
void SideTips::disconnect_mainchain_tip(Txn& t, const Archive& a, const std::optional<Hash32>& prev,
                                        const std::optional<Hash32>& commitment) const
{
    auto cur = mainchain_tip(t);
    if (!cur) throw SideTipsError("no mainchain tip to disconnect");
    auto tip = a.need_main(t, *cur);
    std::optional<Hash32> new_tip;
    if (prev) {
        auto p = a.need_main(t, *prev);
        if (p.hash != tip.prev) throw SideTipsError("invalid mainchain parent, expected (" + main_hex(tip.prev) + ")");
        if (p.height + 1 != tip.height)
            throw SideTipsError("invalid mainchain parent height, expected (" + std::to_string(tip.height) + " - 1)");
        if (!tip.prev.is_zero()) new_tip = p.hash;
    } else if (!tip.prev.is_zero()) {
        throw SideTipsError("invalid mainchain parent, expected (" + main_hex(tip.prev) + ")");
    }
    if (commitment) {
        auto i = info(t, *commitment);
        // a commitment to a block outside the tip set (unknown, body never received, failed
        // BMM) fails here: their mainchain task then fails on every retry; likewise a block
        // whose recorded main block was disconnected before (and reconnected: it is never
        // re-ordered), which is no longer ordered
        bool missing = !i || (i->main_block_hash == tip.hash && !t.del(T_ORDERED, ordered_key(*i)));
        if (missing) {
            std::string e = "missing sidechain tip (" + side_hex(*commitment) + ")";
            if (halt_on_missing_commitment) throw SideTipsError(e);
            LOG_WARN("disconnecting mainchain block %s: %s; ignored (their node halts here)", main_hex(tip.hash).c_str(), e.c_str());
        }
    }
    if (new_tip) t.put(T_MAIN_TIP, unit_key(), new_tip->span());
    else t.del(T_MAIN_TIP, unit_key());
}

// mainchain_task.rs:270-412
size_t sync_side_tips(Txn& t, const Archive& a, const SideTips& st, const Hash32& main_tip,
                      const std::function<void(uint32_t, uint32_t, uint32_t)>& progress)
{
    auto side_main = st.mainchain_tip(t);
    Hash32 common;
    if (side_main && !main_tip.is_zero()) common = a.last_common_main_ancestor(t, main_tip, *side_main);
    size_t events = 0;
    std::optional<Hash32> cur = side_main;
    // disconnect mainchain state tip until common ancestor is reached
    while (cur && *cur != common) {
        auto hi = a.need_main(t, *cur);
        std::optional<Hash32> prev;
        if (!hi.prev.is_zero()) prev = a.need_main(t, hi.prev).hash;
        if (!a.has_main_block_info(t, *cur)) throw bt::sidechain::ArchiveError("no mainchain block info for block hash " + main_hex(*cur));
        auto commitment = a.main_block_info(t, *cur).bmm_commitment;
        st.disconnect_mainchain_tip(t, a, prev, commitment);
        events++;
        cur = prev;
    }
    // connect mainchain state tip until mainchain tip is reached
    if (tip_or_zero(cur) == main_tip) return events;
    std::vector<Hash32> path; // main_tip back to (excluding) cur
    for (Hash32 h = main_tip; !h.is_zero() && h != tip_or_zero(cur);) {
        path.push_back(h);
        h = a.need_main(t, h).prev;
    }
    uint32_t tip_height = a.need_main(t, main_tip).height;
    uint32_t total = uint32_t(path.size()), done = 0;
    if (progress) progress(0, total, tip_height);
    for (auto it = path.rbegin(); it != path.rend(); ++it) {
        const Hash32& main = *it;
        if (!a.has_main_block_info(t, main)) throw bt::sidechain::ArchiveError("no mainchain block info for block hash " + main_hex(main));
        auto bi = a.main_block_info(t, main);
        std::optional<std::pair<Hash32, std::optional<Hash32>>> commitment;
        // an invalidated block has no body in their archive (invalidate_block deletes it)
        if (bi.bmm_commitment && a.has_body(t, *bi.bmm_commitment) && !a.invalid(t, *bi.bmm_commitment)) {
            const Hash32& side = *bi.bmm_commitment;
            auto sh = a.need_header(t, side);
            if (!sh.prev_side_hash || st.contains(t, *sh.prev_side_hash)) {
                auto res = a.bmm_results(t, side);
                auto r = res.find(main);
                if (r == res.end()) throw bt::sidechain::ArchiveError("no BMM result with block " + side_hex(side));
                if (r->second == BmmResult::Verified) commitment = std::make_pair(side, sh.prev_side_hash);
            }
        }
        st.connect_mainchain_tip(t, a, main, commitment);
        events++;
        if (progress && (++done % 32 == 0 || done == total)) progress(done, total, tip_height);
    }
    return events;
}

// archive/mod.rs:672-730
void side_tips_put_body(Txn& t, const Archive& a, const SideTips& st, const Hash32& block)
{
    if (a.invalid(t, block)) return;
    Hash32 main_tip = tip_or_zero(st.mainchain_tip(t));
    std::deque<Hash32> queue;
    auto update = [&](const Hash32& h, const Header& hd) {
        bool connected = false;
        // their HashMap order; at most one Verified main block (a child of prev_main) can be
        // on the active mainchain, so the order does not matter
        for (auto& [m, r] : a.bmm_results(t, h)) {
            if (r != BmmResult::Verified) continue;
            if (hd.prev_side_hash && !st.contains(t, *hd.prev_side_hash)) continue;
            if (!a.is_main_descendant(t, m, main_tip)) continue; // throws without a mainchain tip
            st.connect_sidechain_tip(t, m, a.total_work(t, m), h, hd.prev_side_hash);
            connected = true;
        }
        if (connected)
            for (auto& s : a.successors(t, h)) queue.push_back(s);
    };
    update(block, a.need_header(t, block));
    while (!queue.empty()) {
        Hash32 h = queue.front();
        queue.pop_front();
        if (!a.has_body(t, h) || a.invalid(t, h)) continue;
        update(h, a.need_header(t, h));
    }
}

// archive/mod.rs:761-776
void side_tips_delete_body(Txn& t, const Archive& a, const SideTips& st, const Hash32& block)
{
    std::deque<Hash32> queue{block};
    while (!queue.empty()) {
        Hash32 h = queue.front();
        queue.pop_front();
        if (!st.contains(t, h)) continue;
        st.disconnect_sidechain_tip(t, h);
        for (auto& s : a.successors(t, h)) queue.push_back(s);
    }
}

bool side_tips_tip_ready(const Txn& t, const Archive& a, const SideTips& st, const TipRef& tip)
{
    // policy: never an operator-invalidated block (its descendants are marked invalid with it
    // and no new descendant can be stored: the header is gone)
    if (!st.contains(t, tip.block_hash) || a.invalid(t, tip.block_hash)) return false;
    return a.is_main_descendant(t, tip.main_block_hash, tip_or_zero(st.mainchain_tip(t)));
}

bool side_tips_peer_tip_relevant(const Txn& t, const Archive& a, const SideTips& st, const Hash32& peer_main)
{
    if (!a.main_header(t, peer_main)) return false;
    auto side_main = st.mainchain_tip(t);
    if (!side_main) return false;
    return a.is_main_descendant(t, peer_main, *side_main);
}

} // namespace bitnames
