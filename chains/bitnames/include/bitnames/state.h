// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// BitNames state machine: a literal port of the plain-bitnames fork v0.18.2
// lib/state/{mod,block,bitnames,two_way_peg_data,rollback}.rs over our ordered KV store.
// Tables and key encodings mirror their LMDB databases where the order is observable
// (deposit_blocks keyed by little-endian u32 under memcmp order; seq_to_bitname by u32 BE;
// bitnames by the 32-byte name hash).
#pragma once

#include <bitnames/types.h>

#include <bt/kv.h>
#include <bt/mainchain.h>

#include <stdexcept>

namespace bitnames {

constexpr uint32_t WITHDRAWAL_BUNDLE_FAILURE_GAP = 4; // lib/state/mod.rs:37

/** A consensus failure. `panic` marks paths where their node panics instead of erroring;
 *  the network cannot connect such a block either, so we reject it too. */
struct StateError : std::runtime_error {
    bool panic = false;
    explicit StateError(const std::string& m, bool p = false) : std::runtime_error(m), panic(p) {}
};

enum class BundleStatus : uint8_t { Confirmed = 0, Dropped = 1, Failed = 2, Pending = 3, Submitted = 4, SubmittedUnexpected = 5 };
const char* to_string(BundleStatus s);

template <class T>
struct HeightStamped {
    T value;
    uint32_t height;
};
/** rollback.rs RollBack<HeightStamped<T>>: NonEmpty, push refuses a lower height. */
template <class T>
struct RollBack {
    std::vector<HeightStamped<T>> v; // never empty
    static RollBack make(T x, uint32_t h) { return RollBack{{{x, h}}}; }
    const HeightStamped<T>& latest() const { return v.back(); }
    bool push(T x, uint32_t h)
    {
        if (v.back().height > h) return false;
        v.push_back({x, h});
        return true;
    }
    std::pair<std::optional<RollBack>, HeightStamped<T>> pop() const
    {
        if (v.size() > 1) {
            RollBack r = *this;
            auto last = r.v.back();
            r.v.pop_back();
            return {r, last};
        }
        return {std::nullopt, v.front()};
    }
};

/** rollback.rs RollBack<TxidStamped<T>>: NonEmpty, push without checks, pop keeps the head. */
template <class T>
struct TxidStamped {
    T data;
    Hash32 txid;
    uint32_t height;
};
template <class T>
struct TxHistory {
    std::vector<TxidStamped<T>> v; // never empty
    const TxidStamped<T>& latest() const { return v.back(); }
    /** at_block_height: the last value stamped at or below height. */
    const TxidStamped<T>* at_block_height(uint32_t h) const
    {
        for (auto it = v.rbegin(); it != v.rend(); ++it)
            if (it->height <= h) return &*it;
        return nullptr;
    }
};

/** types::BitNameData: what RPC returns. */
struct BitNameData {
    uint32_t seq_id = 0;
    MutableBitNameData data;
};

/** lib/state/bitnames.rs BitNameData: per-field histories. */
struct BitNameRecord {
    uint32_t seq_id = 0;
    TxHistory<std::optional<Hash32>> commitment;
    bool is_icann = false;
    TxHistory<std::optional<SocketV4>> socket_addr_v4;
    TxHistory<std::optional<SocketV6>> socket_addr_v6;
    TxHistory<std::optional<bt::ByteArray<32>>> encryption_pubkey;
    TxHistory<std::optional<bt::frost::Point>> signing_pubkey;
    TxHistory<std::optional<uint64_t>> paymail_fee_sats;

    static BitNameRecord init(const MutableBitNameData& d, const Hash32& txid, uint32_t height, uint32_t seq);
    BitNameData current() const;
    std::optional<BitNameData> at_block_height(uint32_t h) const;
    void apply_updates(const BitNameDataUpdates& u, const Hash32& txid, uint32_t height);
    /** revert_updates: their assert!s become panic errors. */
    void revert_updates(const BitNameDataUpdates& u, const Hash32& txid, uint32_t height);
};

/** types/lib.rs WithdrawalBundle */
struct WithdrawalBundle {
    std::map<OutPoint, FilledOutput> spend_utxos; // BTreeMap order
    std::vector<bt::btc::TxOut> outputs;           // full tx outputs: [fee, commitment, payouts...]
    Bytes tx_bytes() const { return bt::btc::serialize_inputless_tx(2, outputs, 0); }
    Hash32 m6id() const { return bt::sha256d(tx_bytes()); }
};
std::optional<WithdrawalBundle> make_withdrawal_bundle(uint32_t block_height, uint64_t fee, std::map<OutPoint, FilledOutput> spend_utxos,
                                                       std::vector<bt::btc::TxOut> payouts);
bool predict_weight_ok(uint32_t n_outputs, uint32_t sum_txout_sizes);

struct WithdrawalBundleInfo {
    enum Kind : uint8_t { Known = 0, Unknown = 1, UnknownConfirmed = 2 } kind = Unknown;
    WithdrawalBundle bundle;                      // Known
    std::map<OutPoint, FilledOutput> spend_utxos; // UnknownConfirmed
};

/** types/lib.rs BlockIndexEvents: coin movements a body does not carry. */
struct BlockIndexEvents {
    std::vector<std::pair<OutPoint, FilledOutput>> deposits;
    std::vector<std::pair<OutPoint, Hash32>> bundle_spends; // (outpoint, m6id)
    bool empty() const { return deposits.empty() && bundle_spends.empty(); }
};

struct PrevalidatedBlock {
    std::vector<FilledTransaction> filled; // point into the block body
    Hash32 merkle_root;
    uint64_t total_fees = 0;
    uint64_t coinbase_value = 0;
    uint32_t next_height = 0;
};

class State {
public:
    enum Table : uint8_t {
        T_TIP = 1, T_HEIGHT, T_UTXOS, T_STXOS, T_PENDING_BUNDLE, T_LATEST_FAILED, T_BUNDLES, T_DEPOSIT_BLOCKS,
        T_BUNDLE_EVENT_BLOCKS, T_BLOCK_INDEX_EVENTS, T_BITNAMES, T_RESERVATIONS, T_SEQ_TO_BITNAME
    };

    std::optional<Hash32> tip(const bt::kv::Txn& t) const;
    std::optional<uint32_t> height(const bt::kv::Txn& t) const;
    std::optional<FilledOutput> utxo(const bt::kv::Txn& t, const OutPoint& op) const;
    std::optional<SpentOutput> stxo(const bt::kv::Txn& t, const OutPoint& op) const;
    std::vector<std::pair<OutPoint, FilledOutput>> utxos(const bt::kv::Txn& t) const;
    std::vector<std::pair<OutPoint, SpentOutput>> stxos(const bt::kv::Txn& t) const;
    std::optional<Hash32> pending_bundle_m6id(const bt::kv::Txn& t) const;
    std::optional<std::pair<WithdrawalBundleInfo, RollBack<BundleStatus>>> bundle(const bt::kv::Txn& t, const Hash32& m6id) const;
    std::vector<std::pair<Hash32, std::pair<WithdrawalBundleInfo, RollBack<BundleStatus>>>> bundles(const bt::kv::Txn& t) const;
    std::optional<std::pair<WithdrawalBundle, uint32_t>> pending_bundle(const bt::kv::Txn& t) const;
    std::optional<std::pair<uint32_t, Hash32>> latest_failed_bundle(const bt::kv::Txn& t) const;
    std::optional<RollBack<Hash32>> latest_failed_rollback(const bt::kv::Txn& t) const;
    std::vector<std::pair<uint32_t, std::pair<Hash32, uint32_t>>> deposit_blocks(const bt::kv::Txn& t) const;
    std::vector<std::pair<uint32_t, std::pair<Hash32, uint32_t>>> bundle_event_blocks(const bt::kv::Txn& t) const;
    BlockIndexEvents block_index_events(const bt::kv::Txn& t, uint32_t height) const;
    uint64_t sidechain_wealth(const bt::kv::Txn& t) const;

    // ---- BitNames tables (lib/state/bitnames.rs Dbs)
    std::optional<BitNameRecord> bitname(const bt::kv::Txn& t, const Hash32& name) const;
    /** All names in key (name hash) order. */
    std::vector<std::pair<Hash32, BitNameRecord>> bitnames(const bt::kv::Txn& t) const;
    std::optional<Hash32> reservation(const bt::kv::Txn& t, const Hash32& txid) const;
    std::vector<std::pair<Hash32, Hash32>> reservations(const bt::kv::Txn& t) const;
    std::vector<std::pair<uint32_t, Hash32>> seq_to_bitname(const bt::kv::Txn& t) const;
    /** Bitname data at a height (at_block_height); nullopt if the name or a field did not exist. */
    std::optional<BitNameData> bitname_at(const bt::kv::Txn& t, const Hash32& name, uint32_t height) const;

    // ---- transactions (lib/state/mod.rs)
    FilledTransaction fill(const bt::kv::Txn& t, const Transaction& tx) const;
    /** fill_transaction_from_stxos: inputs already spent by this tx (asserts the inpoint). */
    FilledTransaction fill_from_stxos(const bt::kv::Txn& t, const Transaction& tx) const;
    static void validate_reservations(const FilledTransaction& ft);
    void validate_bitnames(const bt::kv::Txn& t, const FilledTransaction& ft) const;
    static void validate_batch_icann(const FilledTransaction& ft);
    /** validate_filled_transaction: rules above, no withdrawal spends; returns the fee. */
    uint64_t validate_filled(const bt::kv::Txn& t, const FilledTransaction& ft) const;
    /** validate_transaction (mempool / submit_transaction); returns the fee. */
    uint64_t validate_transaction(const bt::kv::Txn& t, const AuthorizedTransaction& tx) const;

    // ---- blocks (lib/state/block.rs)
    struct CheckOpts {
        bool authorizations = true;
    };
    PrevalidatedBlock prevalidate(const bt::kv::Txn& t, const Header& h, const Body& b, CheckOpts opts) const;
    PrevalidatedBlock prevalidate(const bt::kv::Txn& t, const Header& h, const Body& b) const { return prevalidate(t, h, b, CheckOpts{}); }
    void connect_prevalidated(bt::kv::Txn& t, const Header& h, const Body& b, const PrevalidatedBlock& pre) const;
    void disconnect_tip(bt::kv::Txn& t, const Header& h, const Body& b) const;

    // ---- two-way peg (lib/state/two_way_peg_data.rs)
    void connect_2wpd(bt::kv::Txn& t, const bt::mainchain::TwoWayPegData& d) const;
    void disconnect_2wpd(bt::kv::Txn& t, const bt::mainchain::TwoWayPegData& d) const;
    std::optional<WithdrawalBundle> collect_withdrawal_bundle(const bt::kv::Txn& t, uint32_t block_height) const;
    /** proto.rs:447-517: s2_ form or bare base58 of 20 bytes, else ALL_ZEROS. */
    static FilledOutput deposit_output(const bt::mainchain::Deposit& d);

private:
    void put_utxo(bt::kv::Txn& t, const OutPoint& op, const FilledOutput& o) const;
    void put_stxo(bt::kv::Txn& t, const OutPoint& op, const SpentOutput& s) const;
    void put_bundle(bt::kv::Txn& t, const Hash32& m6id, const WithdrawalBundleInfo& info, const RollBack<BundleStatus>& st) const;
    void put_bitname(bt::kv::Txn& t, const Hash32& name, const BitNameRecord& r) const;
    void apply_registration(bt::kv::Txn& t, const FilledTransaction& ft, uint32_t height) const;
    void revert_registration(bt::kv::Txn& t, const FilledTransaction& ft) const;
    void apply_updates(bt::kv::Txn& t, const FilledTransaction& ft, uint32_t height) const;
    void revert_updates(bt::kv::Txn& t, const FilledTransaction& ft, uint32_t height) const;
    void apply_batch_icann(bt::kv::Txn& t, const FilledTransaction& ft) const;
    void revert_batch_icann(bt::kv::Txn& t, const FilledTransaction& ft) const;
    void connect_bundle_submitted(bt::kv::Txn& t, uint32_t h, BlockIndexEvents& ev, const Hash32& m6id) const;
    void connect_bundle_confirmed(bt::kv::Txn& t, uint32_t h, const Hash32& m6id) const;
    void connect_bundle_failed(bt::kv::Txn& t, uint32_t h, const Hash32& m6id) const;
    void disconnect_bundle_submitted(bt::kv::Txn& t, uint32_t h, const Hash32& m6id) const;
    void disconnect_bundle_confirmed(bt::kv::Txn& t, uint32_t h, const Hash32& m6id) const;
    void disconnect_bundle_failed(bt::kv::Txn& t, uint32_t h, const Hash32& m6id) const;
};

// value encodings (also used by the RPC layer)
void enc_bundle_info(Writer& w, const WithdrawalBundleInfo& i);
WithdrawalBundleInfo dec_bundle_info(Reader& r);

} // namespace bitnames
