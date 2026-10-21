// Mainchain reorgs under the fork's side-tips rule (plain-bitnames v0.18.2 a38200d,
// lib/archive/side_tips/mod.rs:295-359, lib/node/net_task.rs:928-980), a quirk reproduced on
// purpose: sidechain blocks whose BMM mainchain block is reorged away stay connected, and the
// sidechain moves only when better_tip prefers another tip. Lab finding 2026-10-21 (their node
// kept 2 such blocks, ours dropped them). Each test drives the node's own mainchain handling
// (Node::sync_to_mainchain_tip) on an in-memory store.
#include "test.h"

#include <bitnames/node.h>

using namespace bitnames;
using bt::kv::Txn;

namespace {

/** Mainchain block `height` of branch `branch` (0 = the first chain). */
Hash32 M(uint32_t height, uint8_t branch = 0)
{
    Hash32 h;
    h[0] = uint8_t(height);
    h[1] = uint8_t(height >> 8);
    h[2] = branch;
    h[31] = 0x4d;
    return h;
}

struct Lab {
    Node node{NodeConfig{}};
    std::map<Hash32, Header> side; // by hash

    Lab() { node.attach_store(std::make_unique<bt::kv::MemStore>()); }

    /** A mainchain block of work 1 (total work = height + 1), optionally BMM-committing. */
    Hash32 main(const Hash32& h, const std::optional<Hash32>& prev, std::optional<Hash32> commitment = std::nullopt)
    {
        Txn t(node.store());
        bt::mainchain::BlockHeaderInfo hi;
        hi.block_hash = h;
        hi.prev_block_hash = prev ? *prev : Hash32{};
        hi.height = prev ? node.archive().need_main(t, *prev).height + 1 : 0;
        hi.work[0] = 1;
        node.archive().put_main_header_info(t, hi);
        bt::mainchain::BlockInfo bi;
        bi.bmm_commitment = commitment;
        node.archive().put_main_block_info(t, h, bi);
        t.commit();
        return h;
    }
    /** An empty sidechain block, received (header + body) but not connected. */
    Hash32 block(const std::optional<Hash32>& prev_side, const Hash32& prev_main)
    {
        Header h;
        h.merkle_root = *compute_merkle_root(Coinbase{}, {});
        h.prev_side_hash = prev_side;
        h.prev_main_hash = prev_main;
        node.receive_block(h, Body{});
        side[h.hash()] = h;
        return h.hash();
    }
    bool sync(const Hash32& main_tip) { return node.sync_to_mainchain_tip(main_tip); }
    std::optional<Hash32> tip() { return node.tip(); }
    std::optional<uint32_t> height() { return node.height(); }
    bool in_tips(const Hash32& s)
    {
        Txn t(node.store());
        return node.side_tips().contains(t, s);
    }
    bool ordered(const Hash32& s)
    {
        Txn t(node.store());
        return node.side_tips().in_ordered(t, s);
    }
    std::optional<Hash32> best()
    {
        Txn t(node.store());
        auto b = node.side_tips().best(t);
        return b ? std::optional<Hash32>(b->first) : std::nullopt;
    }
    std::optional<Hash32> side_main_tip()
    {
        Txn t(node.store());
        return node.side_tips().mainchain_tip(t);
    }
    bool ready(const Hash32& s, const Hash32& m)
    {
        Txn t(node.store());
        return side_tips_tip_ready(t, node.archive(), node.side_tips(), TipRef{s, m});
    }
    bool peer_relevant(const Hash32& m)
    {
        Txn t(node.store());
        return side_tips_peer_tip_relevant(t, node.archive(), node.side_tips(), m);
    }
    std::optional<BmmResult> bmm(const Hash32& s, const Hash32& m)
    {
        Txn t(node.store());
        auto r = node.archive().bmm_results(t, s);
        auto it = r.find(m);
        return it == r.end() ? std::nullopt : std::optional<BmmResult>(it->second);
    }

    // The lab chain: M0..M6, S0..S4 committed in M2..M6 (S_i's prev_main = M_{i+1}).
    std::vector<Hash32> S;
    void build_lab_chain()
    {
        main(M(0), std::nullopt);
        main(M(1), M(0));
        for (uint32_t i = 0; i < 5; i++) {
            Hash32 s = block(i ? std::optional<Hash32>(S.back()) : std::nullopt, M(i + 1));
            S.push_back(s);
            main(M(i + 2), M(i + 1), s);
        }
        CHECK(sync(M(6)));
    }
    /** The lab reorg: M5, M6 (BMM of S3, S4) replaced by M5'..M7' without commitments. */
    void lab_reorg()
    {
        main(M(5, 1), M(4));
        main(M(6, 1), M(5, 1));
        main(M(7, 1), M(6, 1));
        CHECK(sync(M(7, 1)));
    }
};

} // namespace

TEST(side_tips_follow_bmm_on_the_mainchain)
{
    Lab l;
    l.build_lab_chain();
    // the mainchain event reorgs to the best ordered side tip
    CHECK(l.tip() == l.S[4]);
    CHECK_EQ(*l.height(), 4u);
    CHECK(l.best() == l.S[4]);
    CHECK(l.side_main_tip() == M(6));
    for (auto& s : l.S) CHECK(l.in_tips(s) && l.ordered(s));
    CHECK(l.ready(l.S[4], M(6)));
}

TEST(mainchain_reorg_keeps_sidechain_blocks_whose_bmm_block_left)
{
    // The lab scenario: their node kept the last 2 sidechain blocks (36 vs our 34).
    Lab l;
    l.build_lab_chain();
    l.lab_reorg();
    CHECK(l.side_main_tip() == M(7, 1));
    CHECK(l.tip() == l.S[4]); // kept: Thunder's port would be at S2
    CHECK_EQ(*l.height(), 4u);
    // S3, S4 stay in the tip set but left the ordered tips; the best ordered tip is S2, and
    // better_tip(S4@M6, S2@M4) keeps S4 (higher, more work)
    CHECK(l.in_tips(l.S[3]) && l.in_tips(l.S[4]));
    CHECK(!l.ordered(l.S[3]) && !l.ordered(l.S[4]));
    CHECK(l.best() == l.S[2]);
    // the tip still reports its stale BMM block (best_main_verification = M6)
    CHECK(l.node.best_main_verification(l.S[4]) == M(6));
    // a peer advertising S4@M6 is ignored, and S4@M6 is not ready to reorg to
    CHECK(!l.peer_relevant(M(6)));
    CHECK(!l.ready(l.S[4], M(6)));
}

TEST(kept_blocks_are_replaced_by_the_next_block_on_the_new_mainchain)
{
    Lab l;
    l.build_lab_chain();
    l.lab_reorg();
    // their template mines (empty) on S2, the last block whose prev_main is still an ancestor;
    // better_tip(S4@M6, S3'@M8'): lower height but more work, and S4's ancestor before the
    // fork point M4 is S2 (height 2 < 3): S3' wins
    Hash32 s3b = l.block(l.S[2], M(7, 1));
    l.main(M(8, 1), M(7, 1), s3b);
    CHECK(l.bmm(s3b, M(8, 1)) == BmmResult::Verified);
    CHECK(l.sync(M(8, 1)));
    CHECK(l.tip() == s3b);
    CHECK_EQ(*l.height(), 3u);
}

TEST(child_of_a_kept_block_fails_bmm_on_the_new_mainchain)
{
    Lab l;
    l.build_lab_chain();
    l.lab_reorg();
    // a block on S4 cannot be BMM-verified: S4's only verification (M6) is off the chain
    Hash32 s5 = l.block(l.S[4], M(7, 1));
    l.main(M(8, 1), M(7, 1), s5);
    CHECK(l.bmm(s5, M(8, 1)) == BmmResult::Failed);
    CHECK(l.sync(M(8, 1)));
    CHECK(!l.in_tips(s5));
    CHECK(l.tip() == l.S[4]);
}

TEST(conflicting_commitment_on_the_new_mainchain_waits_for_better_tip)
{
    Lab l;
    l.build_lab_chain();
    // the new branch commits a competing S3x (on S2) in M6'
    l.main(M(5, 1), M(4));
    Hash32 s3x = l.block(l.S[2], M(5, 1));
    l.main(M(6, 1), M(5, 1), s3x);
    CHECK(l.sync(M(6, 1)));
    // S3x is the best ordered tip, but better_tip(S4@M6, S3x@M6') keeps S4 (higher, equal work)
    CHECK(l.best() == s3x);
    CHECK(l.tip() == l.S[4]);
    // S4x on S3x at M7': equal height, more work on another mainchain lineage: reorg
    Hash32 s4x = l.block(s3x, M(6, 1));
    l.main(M(7, 1), M(6, 1), s4x);
    CHECK(l.sync(M(7, 1)));
    CHECK(l.tip() == s4x);
    CHECK_EQ(*l.height(), 4u);
}

TEST(reorg_back_and_forth_halts_the_side_tips_sync)
{
    // REPRODUCE_SIDE_TIPS_HALT = true (their behaviour)
    Lab l;
    l.node.side_tips().halt_on_missing_commitment = true;
    l.build_lab_chain();
    l.lab_reorg();
    // back to the first chain (longer now): S3/S4 are in the tip set already, so connecting
    // M5/M6 does not re-order them
    l.main(M(7), M(6));
    l.main(M(8), M(7));
    CHECK(l.sync(M(8)));
    CHECK(l.side_main_tip() == M(8));
    CHECK(l.tip() == l.S[4]);
    CHECK(!l.ordered(l.S[3]) && !l.ordered(l.S[4]));
    // away again: disconnecting M6 finds S4 recorded at M6 but not ordered -> "missing
    // sidechain tip"; their mainchain task fails on every retry, the side tips stay at M8
    l.main(M(8, 1), M(7, 1));
    l.main(M(9, 1), M(8, 1));
    CHECK(!l.sync(M(9, 1)));
    CHECK(!l.sync(M(9, 1)));
    CHECK(l.side_main_tip() == M(8));
    CHECK(l.tip() == l.S[4]);
    CHECK(!l.peer_relevant(M(9, 1))); // peers on the new chain are ignored from now on
}

TEST(reorg_of_a_commitment_to_an_unknown_block_halts_the_side_tips_sync)
{
    // REPRODUCE_SIDE_TIPS_HALT = true (their behaviour)
    Lab l;
    l.node.side_tips().halt_on_missing_commitment = true;
    l.build_lab_chain();
    Hash32 unknown;
    unknown[0] = 0xee;
    l.main(M(7), M(6), unknown); // BMM of a block whose body never arrived
    CHECK(l.sync(M(7)));
    CHECK(!l.in_tips(unknown));
    l.main(M(7, 2), M(6));
    l.main(M(8, 2), M(7, 2));
    CHECK(!l.sync(M(8, 2)));
    CHECK(l.side_main_tip() == M(7));
    CHECK(l.tip() == l.S[4]);
}

TEST(same_block_recommitted_in_a_sibling_mainchain_block)
{
    Lab l;
    l.build_lab_chain();
    // M6 replaced by M6* that commits S4 again (same prev_main M5): verified, not re-ordered
    l.main(M(6, 3), M(5), l.S[4]);
    l.main(M(7, 3), M(6, 3));
    CHECK(l.bmm(l.S[4], M(6, 3)) == BmmResult::Verified);
    CHECK(l.sync(M(7, 3)));
    CHECK(l.tip() == l.S[4]);
    CHECK(!l.ordered(l.S[4]));
    CHECK(l.best() == l.S[3]);
    // S4 stays recorded at M6, so disconnecting M6* is not an error
    l.main(M(7), M(6));
    l.main(M(8), M(7));
    CHECK(l.sync(M(8)));
    CHECK(l.side_main_tip() == M(8));
    CHECK(l.tip() == l.S[4]);
}

TEST(deleted_invalid_body_leaves_the_tip_set_with_descendants)
{
    Lab l;
    l.build_lab_chain();
    {
        Txn t(l.node.store());
        l.node.archive().delete_body(t, l.S[2]);
        side_tips_delete_body(t, l.node.archive(), l.node.side_tips(), l.S[2]);
        t.commit();
    }
    CHECK(l.in_tips(l.S[1]));
    for (int i = 2; i < 5; i++) CHECK(!l.in_tips(l.S[i]) && !l.ordered(l.S[i]));
    CHECK(l.best() == l.S[1]);
}

TEST(body_received_after_its_bmm_block_enters_the_tip_set)
{
    // archive put_body: a body that arrives after the mainchain event joins the tip set (and
    // its waiting descendants), and the next mainchain event reorgs to it
    Lab l;
    l.main(M(0), std::nullopt);
    l.main(M(1), M(0));
    Header h0;
    h0.merkle_root = *compute_merkle_root(Coinbase{}, {});
    h0.prev_main_hash = M(1);
    {
        Txn t(l.node.store());
        l.node.archive().put_header(t, h0);
        t.commit();
    }
    l.main(M(2), M(1), h0.hash());
    CHECK(l.sync(M(2)));
    CHECK(!l.in_tips(h0.hash())); // no body at the event
    l.node.receive_block(h0, Body{});
    CHECK(l.in_tips(h0.hash()) && l.ordered(h0.hash()));
    CHECK(!l.tip());
    l.main(M(3), M(2));
    CHECK(l.sync(M(3)));
    CHECK(l.tip() == h0.hash());
}

TEST(default_does_not_halt_on_a_missing_commitment)
{
    CHECK(!REPRODUCE_SIDE_TIPS_HALT);
    {
        // back and forth over a kept block's BMM block: the sync goes on, the tip stays
        Lab l;
        CHECK(!l.node.side_tips().halt_on_missing_commitment);
        l.build_lab_chain();
        l.lab_reorg();
        l.main(M(7), M(6));
        l.main(M(8), M(7));
        CHECK(l.sync(M(8)));
        l.main(M(8, 1), M(7, 1));
        l.main(M(9, 1), M(8, 1));
        CHECK(l.sync(M(9, 1)));
        CHECK(l.side_main_tip() == M(9, 1));
        CHECK(l.tip() == l.S[4]);
        CHECK(l.peer_relevant(M(9, 1)));
        // and the next block on the new mainchain still replaces the kept ones
        Hash32 s3b = l.block(l.S[2], M(9, 1));
        l.main(M(10, 1), M(9, 1), s3b);
        CHECK(l.sync(M(10, 1)));
        CHECK(l.tip() == s3b);
    }
    {
        // reorg of a commitment to a block never received
        Lab l;
        l.build_lab_chain();
        Hash32 unknown;
        unknown[0] = 0xee;
        l.main(M(7), M(6), unknown);
        CHECK(l.sync(M(7)));
        l.main(M(7, 2), M(6));
        l.main(M(8, 2), M(7, 2));
        CHECK(l.sync(M(8, 2)));
        CHECK(l.side_main_tip() == M(8, 2));
        CHECK(l.tip() == l.S[4]);
    }
}

TEST(rebuilt_side_tips_follow_the_active_mainchain)
{
    // --bt-rebuild-side-tips: the index is rebuilt from the active mainchain; a kept block
    // whose BMM block is gone is then outside it and is disconnected (with its 2WPD)
    Lab l;
    l.build_lab_chain();
    l.lab_reorg();
    CHECK(l.tip() == l.S[4]);
    {
        Txn t(l.node.store());
        l.node.side_tips().clear(t);
        t.commit();
    }
    CHECK(l.sync(M(7, 1)));
    CHECK(!l.in_tips(l.S[3]) && !l.in_tips(l.S[4]));
    CHECK(l.tip() == l.S[2]);
    CHECK_EQ(*l.height(), 2u);
}

TEST(invalidated_block_is_never_reselected)
{
    Lab l;
    l.build_lab_chain();
    l.node.invalidate_block(l.S[3]);
    CHECK(l.tip() == l.S[2]);
    CHECK(!l.in_tips(l.S[3]) && !l.in_tips(l.S[4]));
    CHECK(l.best() == l.S[2]);
    CHECK(!l.ready(l.S[3], M(5)) && !l.ready(l.S[4], M(6)));
    // a later mainchain event does not bring them back
    l.main(M(7), M(6));
    CHECK(l.sync(M(7)));
    CHECK(l.tip() == l.S[2]);
    // nor does a rebuild of the index (their invalidate_block deletes the body too)
    {
        Txn t(l.node.store());
        l.node.side_tips().clear(t);
        t.commit();
    }
    CHECK(l.sync(M(7)));
    CHECK(!l.in_tips(l.S[3]) && !l.in_tips(l.S[4]));
    CHECK(l.tip() == l.S[2]);
}

TEST(peer_body_is_checked_against_its_header)
{
    Lab l;
    l.build_lab_chain();
    Header h;
    h.merkle_root = *compute_merkle_root(Coinbase{}, {});
    h.prev_side_hash = l.S[4];
    h.prev_main_hash = M(6);
    {
        Txn t(l.node.store());
        l.node.archive().put_header(t, h);
        t.commit();
    }
    CHECK(l.node.check_peer_body(h.hash(), Body{}).empty());
    // a body that does not match the header's merkle root (parent = our tip: prevalidated)
    Body bad;
    Output o;
    o.content.kind = Content::Bitcoin;
    o.content.value = 0;
    bad.coinbase.outputs.push_back(o);
    CHECK(!l.node.check_peer_body(h.hash(), bad).empty());
    // a block whose parent is not our tip cannot be checked without its parent state
    CHECK(l.node.check_peer_body(l.S[3], bad).empty());
}
