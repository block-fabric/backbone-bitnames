// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// The fork's side-tips index (plain-bitnames v0.18.2 a38200d lib/archive/side_tips/mod.rs,
// and its users in lib/archive/mod.rs put_body/delete_body, lib/node/mainchain_task.rs
// sync_side_tips_to_tip and lib/node/net_task.rs handle_mainchain_block_event/NewTipReady).
//
// It decides what a mainchain reorg does to the sidechain, and their rule is a quirk we
// reproduce on purpose (doc/bitnames.md, "Mainchain reorgs"): disconnecting a mainchain block
// removes the sidechain block it BMM-committed only from the ORDERED tips
// (side_tips/mod.rs:339-352), never from the tip set, so the state tip keeps sidechain blocks
// whose BMM block was reorged away; the only "disconnect" (net_task.rs:933-944) fires for a
// state tip outside the tip set, which a mainchain reorg never causes.
#pragma once

#include <bitnames/chain.h>

#include <bt/kv.h>

#include <functional>
#include <optional>
#include <stdexcept>

namespace bitnames {

/** side_tips/mod.rs SidechainTipInfo. `work` = total work of `main_block_hash`. */
struct SideTipInfo {
    uint32_t sidechain_height = 0;
    U256 work;
    /** Main block hash with the least amount of work (the first one recorded). */
    Hash32 main_block_hash;
};

/** The fork's side_tips::Error texts (thiserror Display). */
class SideTipsError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class SideTips {
public:
    // T_MAIN_TIP: () -> main block hash (absent = none, their `tip_info: None`).
    // T_TIPS: side hash -> info (`sidechain_tips`).
    // T_ORDERED: height BE || work BE || main hash -> side hash (`ordered_sidechain_tips`,
    //   LMDB byte order of the bincode key: the same order).
    enum Table : uint8_t { T_MAIN_TIP = 83, T_TIPS = 84, T_ORDERED = 85 };

    std::optional<Hash32> mainchain_tip(const bt::kv::Txn& t) const;
    bool contains(const bt::kv::Txn& t, const Hash32& side) const;
    std::optional<SideTipInfo> info(const bt::kv::Txn& t, const Hash32& side) const;
    /** best_side_tip: the last ordered tip. */
    std::optional<std::pair<Hash32, SideTipInfo>> best(const bt::kv::Txn& t) const;
    bool in_ordered(const bt::kv::Txn& t, const Hash32& side) const;

    /** connect_sidechain_tip: no-op when the block is already in the tip set (even when it is
     *  no longer ordered: it is NOT re-ordered). */
    void connect_sidechain_tip(bt::kv::Txn& t, const Hash32& main, const U256& work, const Hash32& side,
                               const std::optional<Hash32>& prev_side) const;
    /** disconnect_sidechain_tip (delete_body of an invalid body). */
    void disconnect_sidechain_tip(bt::kv::Txn& t, const Hash32& side) const;
    /** connect_mainchain_tip; commitment = (side block, its prev_side_hash). */
    void connect_mainchain_tip(bt::kv::Txn& t, const Archive& a, const Hash32& main,
                               const std::optional<std::pair<Hash32, std::optional<Hash32>>>& commitment) const;
    /** disconnect_mainchain_tip; commitment = the RAW bmm_commitment of the main block. */
    void disconnect_mainchain_tip(bt::kv::Txn& t, const Archive& a, const std::optional<Hash32>& prev,
                                  const std::optional<Hash32>& commitment) const;

private:
    static Bytes ordered_key(const SideTipInfo& i);
};

/** mainchain_task.rs sync_side_tips_to_tip: disconnect to the common ancestor, connect up to
 *  main_tip. Returns the number of mainchain blocks disconnected + connected (= the events
 *  their task emits). Throws (ArchiveError/SideTipsError) as their task fails; the caller
 *  drops the transaction. `progress(done, total, tip_height)` per 32 connected blocks. */
size_t sync_side_tips(bt::kv::Txn& t, const Archive& a, const SideTips& st, const Hash32& main_tip,
                      const std::function<void(uint32_t, uint32_t, uint32_t)>& progress = {});

/** archive/mod.rs put_body's side-tips update (call after Archive::put_body). */
void side_tips_put_body(bt::kv::Txn& t, const Archive& a, const SideTips& st, const Hash32& block);

/** archive/mod.rs delete_body's side-tips update (call after Archive::delete_body). */
void side_tips_delete_body(bt::kv::Txn& t, const Archive& a, const SideTips& st, const Hash32& block);

/** net_task.rs NewTipReady (:1215-1245): a tip is reorged to only when it is in the tip set
 *  and its main block is an ancestor of (or is) the side-tips mainchain tip. */
bool side_tips_tip_ready(const bt::kv::Txn& t, const Archive& a, const SideTips& st, const TipRef& tip);

/** peer/task.rs check_peer_tip_and_request_headers (:57-84): a peer tip is considered only
 *  when its main block is known, the side tips have a mainchain tip, and the peer's main
 *  block is an ancestor of (or is) it. */
bool side_tips_peer_tip_relevant(const bt::kv::Txn& t, const Archive& a, const SideTips& st, const Hash32& peer_main);

} // namespace bitnames
