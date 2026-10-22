// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// Literal port of the plain-bitnames fork v0.18.2 lib/state/{mod.rs, block.rs, bitnames.rs,
// two_way_peg_data.rs}. Function and branch order follow theirs so that every accept/reject
// decision and every state write is identical; their panics (assert!, expect) are
// StateError{panic = true}, which rejects the block their node cannot connect either.
#include <bitnames/state.h>

#include <bt/crypto.h>

#include <algorithm>
#include <set>

namespace bitnames {

using bt::kv::Txn;
using bt::mainchain::TwoWayPegData;

const char* to_string(BundleStatus s)
{
    switch (s) {
    case BundleStatus::Confirmed: return "Confirmed";
    case BundleStatus::Dropped: return "Dropped";
    case BundleStatus::Failed: return "Failed";
    case BundleStatus::Pending: return "Pending";
    case BundleStatus::Submitted: return "Submitted";
    case BundleStatus::SubmittedUnexpected: return "SubmittedUnexpected";
    }
    return "?";
}

// ------------------------------------------------------------------ BitName records
template <class T>
static TxHistory<T> hist(const T& v, const Hash32& txid, uint32_t h)
{
    return TxHistory<T>{{TxidStamped<T>{v, txid, h}}};
}

BitNameRecord BitNameRecord::init(const MutableBitNameData& d, const Hash32& txid, uint32_t height, uint32_t seq)
{
    BitNameRecord r;
    r.seq_id = seq;
    r.commitment = hist(d.commitment, txid, height);
    r.socket_addr_v4 = hist(d.socket_addr_v4, txid, height);
    r.socket_addr_v6 = hist(d.socket_addr_v6, txid, height);
    r.encryption_pubkey = hist(d.encryption_pubkey, txid, height);
    r.signing_pubkey = hist(d.signing_pubkey, txid, height);
    r.paymail_fee_sats = hist(d.paymail_fee_sats, txid, height);
    return r;
}

BitNameData BitNameRecord::current() const
{
    BitNameData d;
    d.seq_id = seq_id;
    d.data.commitment = commitment.latest().data;
    d.data.socket_addr_v4 = socket_addr_v4.latest().data;
    d.data.socket_addr_v6 = socket_addr_v6.latest().data;
    d.data.encryption_pubkey = encryption_pubkey.latest().data;
    d.data.signing_pubkey = signing_pubkey.latest().data;
    d.data.paymail_fee_sats = paymail_fee_sats.latest().data;
    return d;
}

std::optional<BitNameData> BitNameRecord::at_block_height(uint32_t h) const
{
    BitNameData d;
    d.seq_id = seq_id;
    auto c = commitment.at_block_height(h);
    auto v4 = socket_addr_v4.at_block_height(h);
    auto v6 = socket_addr_v6.at_block_height(h);
    auto ek = encryption_pubkey.at_block_height(h);
    auto sk = signing_pubkey.at_block_height(h);
    auto pf = paymail_fee_sats.at_block_height(h);
    if (!c || !v4 || !v6 || !ek || !sk || !pf) return std::nullopt;
    d.data = MutableBitNameData{c->data, v4->data, v6->data, ek->data, sk->data, pf->data};
    return d;
}

template <class T>
static void apply_field(TxHistory<std::optional<T>>& f, const Update<T>& u, const Hash32& txid, uint32_t h)
{
    if (u.kind == Update<T>::Delete) f.v.push_back({std::nullopt, txid, h});
    else if (u.kind == Update<T>::Set) f.v.push_back({u.value, txid, h});
}

void BitNameRecord::apply_updates(const BitNameDataUpdates& u, const Hash32& txid, uint32_t height)
{
    apply_field(commitment, u.commitment, txid, height);
    apply_field(socket_addr_v4, u.socket_addr_v4, txid, height);
    apply_field(socket_addr_v6, u.socket_addr_v6, txid, height);
    apply_field(encryption_pubkey, u.encryption_pubkey, txid, height);
    apply_field(signing_pubkey, u.signing_pubkey, txid, height);
    apply_field(paymail_fee_sats, u.paymail_fee_sats, txid, height);
}

// bitnames.rs:156-234 revert_field_update: NonEmpty::pop keeps the head (None when only
// the head remains), then assert!s on the popped entry.
template <class T>
static void revert_field(TxHistory<std::optional<T>>& f, const Update<T>& u, const Hash32& txid, uint32_t h)
{
    if (u.kind == Update<T>::Retain) return;
    if (f.v.size() < 2) throw StateError("revert_updates: popped.is_some() failed", true);
    auto popped = f.v.back();
    f.v.pop_back();
    if (u.kind == Update<T>::Delete) {
        if (popped.data.has_value()) throw StateError("revert_updates: popped.data.is_none() failed", true);
    } else {
        if (!popped.data.has_value() || !(*popped.data == u.value)) throw StateError("revert_updates: popped value mismatch", true);
    }
    if (popped.txid != txid || popped.height != h) throw StateError("revert_updates: txid/height mismatch", true);
}

void BitNameRecord::revert_updates(const BitNameDataUpdates& u, const Hash32& txid, uint32_t height)
{
    // reverse field order (bitnames.rs:202-231)
    revert_field(paymail_fee_sats, u.paymail_fee_sats, txid, height);
    revert_field(signing_pubkey, u.signing_pubkey, txid, height);
    revert_field(encryption_pubkey, u.encryption_pubkey, txid, height);
    revert_field(socket_addr_v4, u.socket_addr_v4, txid, height);
    revert_field(socket_addr_v6, u.socket_addr_v6, txid, height);
    revert_field(commitment, u.commitment, txid, height);
}

// ------------------------------------------------------------------ withdrawal bundle
static uint32_t varint_size(uint64_t n) { return uint32_t(bt::btc::compact_size_len(n)); }

static std::optional<uint32_t> txout_size(uint32_t spk_size)
{
    uint64_t s = 8ull + varint_size(spk_size) + spk_size;
    if (s > UINT32_MAX) return std::nullopt;
    return uint32_t(s);
}

bool predict_weight_ok(uint32_t n_outputs, uint32_t sum_txout_sizes)
{
    const uint64_t TXIN = 36 + 1 + 0 + 4; // treasury input, empty scriptSig
    uint64_t no = uint64_t(n_outputs) + 2;
    if (no > UINT32_MAX) return false;
    uint64_t sum = uint64_t(*txout_size(34)) + *txout_size(10) + sum_txout_sizes;
    if (sum > UINT32_MAX) return false;
    uint64_t base = 4 + (varint_size(1) + TXIN) + (varint_size(no) + sum) + 4;
    if (base > UINT32_MAX) return false;
    return base * 4 <= 400000; // MAX_STANDARD_WEIGHT
}

std::optional<WithdrawalBundle> make_withdrawal_bundle(uint32_t block_height, uint64_t fee, std::map<OutPoint, FilledOutput> spend_utxos,
                                                       std::vector<bt::btc::TxOut> payouts)
{
    // inputs commitment: hash(Vec<OutPoint> = sorted keys ++ [Regular{0^32, block_height}])  types/lib.rs:373-394
    Writer w;
    w.borsh_len(spend_utxos.size() + 1);
    for (auto& [op, _] : spend_utxos) borsh(w, op);
    borsh(w, OutPoint{OutPoint::Regular, Hash32{}, block_height});
    Hash32 commitment = bt::blake3(w.buf);
    Writer fw;
    fw.u64be(fee);
    WithdrawalBundle b;
    b.spend_utxos = std::move(spend_utxos);
    b.outputs.push_back({0, bt::btc::op_return_push(fw.buf)});
    b.outputs.push_back({0, bt::btc::op_return_push(commitment.span())});
    for (auto& p : payouts) b.outputs.push_back(std::move(p));
    if (bt::btc::inputless_tx_weight(b.outputs) > 400000) return std::nullopt; // BundleTooHeavy
    return b;
}

// ------------------------------------------------------------------ encodings
static Bytes u32le(uint32_t v)
{
    Writer w;
    w.u32(v);
    return w.buf;
}
static Bytes u32be(uint32_t v)
{
    Writer w;
    w.u32be(v);
    return w.buf;
}
static const Bytes UNIT{};

static void enc_spent(Writer& w, const SpentOutput& s)
{
    bincode(w, s.output);
    w.u32(s.inpoint.kind);
    w.raw(s.inpoint.id);
    if (s.inpoint.kind == InPoint::Regular) w.u32(s.inpoint.vin);
}
static SpentOutput dec_spent(Reader& r)
{
    SpentOutput s;
    s.output = de_filled_output(r);
    s.inpoint.kind = InPoint::Kind(r.u32());
    s.inpoint.id = r.array<32>();
    if (s.inpoint.kind == InPoint::Regular) s.inpoint.vin = r.u32();
    return s;
}

static void enc_utxo_map(Writer& w, const std::map<OutPoint, FilledOutput>& m)
{
    w.u64(m.size());
    for (auto& [op, o] : m) {
        bincode(w, op);
        bincode(w, o);
    }
}
static std::map<OutPoint, FilledOutput> dec_utxo_map(Reader& r)
{
    std::map<OutPoint, FilledOutput> m;
    uint64_t n = r.u64();
    for (uint64_t i = 0; i < n; i++) {
        OutPoint op = de_outpoint(r);
        m[op] = de_filled_output(r);
    }
    return m;
}

void enc_bundle_info(Writer& w, const WithdrawalBundleInfo& i)
{
    w.u8(i.kind);
    if (i.kind == WithdrawalBundleInfo::Known) {
        enc_utxo_map(w, i.bundle.spend_utxos);
        w.u64(i.bundle.outputs.size());
        for (auto& o : i.bundle.outputs) {
            w.u64(o.value);
            w.bincode_bytes(o.script_pubkey);
        }
    } else if (i.kind == WithdrawalBundleInfo::UnknownConfirmed) {
        enc_utxo_map(w, i.spend_utxos);
    }
}
WithdrawalBundleInfo dec_bundle_info(Reader& r)
{
    WithdrawalBundleInfo i;
    i.kind = WithdrawalBundleInfo::Kind(r.u8());
    if (i.kind == WithdrawalBundleInfo::Known) {
        i.bundle.spend_utxos = dec_utxo_map(r);
        uint64_t n = r.u64();
        for (uint64_t k = 0; k < n; k++) {
            bt::btc::TxOut o;
            o.value = r.u64();
            o.script_pubkey = r.bincode_bytes();
            i.bundle.outputs.push_back(std::move(o));
        }
    } else if (i.kind == WithdrawalBundleInfo::UnknownConfirmed) {
        i.spend_utxos = dec_utxo_map(r);
    }
    return i;
}

template <class T, class F>
static void enc_rollback(Writer& w, const RollBack<T>& rb, F encv)
{
    w.u64(rb.v.size());
    for (auto& hs : rb.v) {
        encv(w, hs.value);
        w.u32(hs.height);
    }
}
template <class T, class F>
static RollBack<T> dec_rollback(Reader& r, F decv)
{
    RollBack<T> rb;
    uint64_t n = r.u64();
    for (uint64_t i = 0; i < n; i++) {
        T v = decv(r);
        uint32_t h = r.u32();
        rb.v.push_back({v, h});
    }
    if (rb.v.empty()) throw bt::DecodeError("empty RollBack");
    return rb;
}

template <class T, class F>
static void enc_hist(Writer& w, const TxHistory<std::optional<T>>& h, F encv)
{
    w.u64(h.v.size());
    for (auto& e : h.v) {
        w.u8(e.data ? 1 : 0);
        if (e.data) encv(w, *e.data);
        w.raw(e.txid);
        w.u32(e.height);
    }
}
template <class T, class F>
static TxHistory<std::optional<T>> dec_hist(Reader& r, F decv)
{
    TxHistory<std::optional<T>> h;
    uint64_t n = r.u64();
    for (uint64_t i = 0; i < n; i++) {
        TxidStamped<std::optional<T>> e;
        if (r.u8()) e.data = decv(r);
        e.txid = r.array<32>();
        e.height = r.u32();
        h.v.push_back(std::move(e));
    }
    if (h.v.empty()) throw bt::DecodeError("empty history");
    return h;
}

static Bytes enc_record(const BitNameRecord& b)
{
    Writer w;
    w.u32(b.seq_id);
    enc_hist(w, b.commitment, [](Writer& x, const Hash32& v) { x.raw(v); });
    w.u8(b.is_icann ? 1 : 0);
    enc_hist(w, b.socket_addr_v4, [](Writer& x, const SocketV4& v) {
        x.raw(ByteSpan(v.ip.data(), 4));
        x.u16(v.port);
    });
    enc_hist(w, b.socket_addr_v6, [](Writer& x, const SocketV6& v) {
        x.raw(ByteSpan(v.ip.data(), 16));
        x.u16(v.port);
    });
    enc_hist(w, b.encryption_pubkey, [](Writer& x, const bt::ByteArray<32>& v) { x.raw(v); });
    enc_hist(w, b.signing_pubkey, [](Writer& x, const bt::frost::Point& v) { x.raw(v); });
    enc_hist(w, b.paymail_fee_sats, [](Writer& x, uint64_t v) { x.u64(v); });
    return w.buf;
}

static BitNameRecord dec_record(ByteSpan b)
{
    Reader r(b);
    BitNameRecord x;
    x.seq_id = r.u32();
    x.commitment = dec_hist<Hash32>(r, [](Reader& rr) { return rr.array<32>(); });
    x.is_icann = r.u8() != 0;
    x.socket_addr_v4 = dec_hist<SocketV4>(r, [](Reader& rr) {
        SocketV4 s;
        auto a = rr.array<4>();
        std::copy(a.begin(), a.end(), s.ip.begin());
        s.port = rr.u16();
        return s;
    });
    x.socket_addr_v6 = dec_hist<SocketV6>(r, [](Reader& rr) {
        SocketV6 s;
        auto a = rr.array<16>();
        std::copy(a.begin(), a.end(), s.ip.begin());
        s.port = rr.u16();
        return s;
    });
    x.encryption_pubkey = dec_hist<bt::ByteArray<32>>(r, [](Reader& rr) { return rr.array<32>(); });
    x.signing_pubkey = dec_hist<bt::frost::Point>(r, [](Reader& rr) { return rr.array<32>(); });
    x.paymail_fee_sats = dec_hist<uint64_t>(r, [](Reader& rr) { return rr.u64(); });
    return x;
}

static Bytes m6id_key(const Hash32& m)
{
    Writer w;
    w.bincode_bytes(m.span()); // SerdeBincode<M6id>: u64 length + 32 bytes
    return w.buf;
}

// ------------------------------------------------------------------ getters
std::optional<Hash32> State::tip(const Txn& t) const
{
    auto v = t.get(T_TIP, UNIT);
    if (!v) return std::nullopt;
    return Hash32::from_span(*v);
}

std::optional<uint32_t> State::height(const Txn& t) const
{
    auto v = t.get(T_HEIGHT, UNIT);
    if (!v) return std::nullopt;
    Reader r(*v);
    return r.u32();
}

std::optional<FilledOutput> State::utxo(const Txn& t, const OutPoint& op) const
{
    auto k = op.key();
    auto v = t.get(T_UTXOS, ByteSpan(k.data(), k.size()));
    if (!v) return std::nullopt;
    Reader r(*v);
    return de_filled_output(r);
}

std::optional<SpentOutput> State::stxo(const Txn& t, const OutPoint& op) const
{
    auto k = op.key();
    auto v = t.get(T_STXOS, ByteSpan(k.data(), k.size()));
    if (!v) return std::nullopt;
    Reader r(*v);
    return dec_spent(r);
}

void State::put_utxo(Txn& t, const OutPoint& op, const FilledOutput& o) const
{
    auto k = op.key();
    Writer w;
    bincode(w, o);
    t.put(T_UTXOS, ByteSpan(k.data(), k.size()), w.buf);
}

void State::put_stxo(Txn& t, const OutPoint& op, const SpentOutput& s) const
{
    auto k = op.key();
    Writer w;
    enc_spent(w, s);
    t.put(T_STXOS, ByteSpan(k.data(), k.size()), w.buf);
}

std::vector<std::pair<OutPoint, FilledOutput>> State::utxos(const Txn& t) const
{
    std::vector<std::pair<OutPoint, FilledOutput>> r;
    t.scan(T_UTXOS, [&](ByteSpan k, ByteSpan v) {
        Reader rd(v);
        r.emplace_back(OutPoint::from_key(k), de_filled_output(rd));
        return true;
    });
    return r;
}

std::vector<std::pair<OutPoint, SpentOutput>> State::stxos(const Txn& t) const
{
    std::vector<std::pair<OutPoint, SpentOutput>> r;
    t.scan(T_STXOS, [&](ByteSpan k, ByteSpan v) {
        Reader rd(v);
        r.emplace_back(OutPoint::from_key(k), dec_spent(rd));
        return true;
    });
    return r;
}

std::optional<Hash32> State::pending_bundle_m6id(const Txn& t) const
{
    auto v = t.get(T_PENDING_BUNDLE, UNIT);
    if (!v) return std::nullopt;
    return Hash32::from_span(*v);
}

static BundleStatus dec_status(Reader& r) { return BundleStatus(r.u8()); }
static void enc_status(Writer& w, BundleStatus s) { w.u8(uint8_t(s)); }

std::optional<std::pair<WithdrawalBundleInfo, RollBack<BundleStatus>>> State::bundle(const Txn& t, const Hash32& m6id) const
{
    auto v = t.get(T_BUNDLES, m6id_key(m6id));
    if (!v) return std::nullopt;
    Reader r(*v);
    auto info = dec_bundle_info(r);
    auto st = dec_rollback<BundleStatus>(r, dec_status);
    return std::make_pair(std::move(info), std::move(st));
}

std::vector<std::pair<Hash32, std::pair<WithdrawalBundleInfo, RollBack<BundleStatus>>>> State::bundles(const Txn& t) const
{
    std::vector<std::pair<Hash32, std::pair<WithdrawalBundleInfo, RollBack<BundleStatus>>>> res;
    t.scan(T_BUNDLES, [&](ByteSpan k, ByteSpan v) {
        Reader r(v);
        auto info = dec_bundle_info(r);
        auto st = dec_rollback<BundleStatus>(r, dec_status);
        res.emplace_back(Hash32::from_span(k.subspan(8)), std::make_pair(std::move(info), std::move(st)));
        return true;
    });
    return res;
}

void State::put_bundle(Txn& t, const Hash32& m6id, const WithdrawalBundleInfo& info, const RollBack<BundleStatus>& st) const
{
    Writer w;
    enc_bundle_info(w, info);
    enc_rollback(w, st, enc_status);
    t.put(T_BUNDLES, m6id_key(m6id), w.buf);
}

std::optional<RollBack<Hash32>> State::latest_failed_rollback(const Txn& t) const
{
    auto v = t.get(T_LATEST_FAILED, UNIT);
    if (!v) return std::nullopt;
    Reader r(*v);
    return dec_rollback<Hash32>(r, [](Reader& rd) { return rd.array<32>(); });
}

static void put_latest_failed(Txn& t, const RollBack<Hash32>& rb)
{
    Writer w;
    enc_rollback(w, rb, [](Writer& ww, const Hash32& h) { ww.raw(h); });
    t.put(State::T_LATEST_FAILED, UNIT, w.buf);
}

// mod.rs:290-319
std::optional<std::pair<uint32_t, Hash32>> State::latest_failed_bundle(const Txn& t) const
{
    auto rb = latest_failed_rollback(t);
    if (!rb) return std::nullopt;
    Hash32 m6id = rb->latest().value;
    auto b = bundle(t, m6id);
    if (!b) throw StateError("Inconsistent DBs: latest failed m6id missing", true);
    for (auto it = b->second.v.rbegin(); it != b->second.v.rend(); ++it)
        if (it->value == BundleStatus::Failed) return std::make_pair(it->height, m6id);
    throw StateError("missing failure status", true);
}

std::optional<std::pair<WithdrawalBundle, uint32_t>> State::pending_bundle(const Txn& t) const
{
    auto m = pending_bundle_m6id(t);
    if (!m) return std::nullopt;
    auto b = bundle(t, *m);
    if (!b) throw StateError("pending bundle missing from withdrawal_bundles");
    if (b->first.kind != WithdrawalBundleInfo::Known) throw StateError("PendingWithdrawalBundleUnknown");
    return std::make_pair(b->first.bundle, b->second.latest().height);
}

static std::vector<std::pair<uint32_t, std::pair<Hash32, uint32_t>>> seq_table(const Txn& t, uint8_t table)
{
    std::vector<std::pair<uint32_t, std::pair<Hash32, uint32_t>>> r;
    t.scan(table, [&](ByteSpan k, ByteSpan v) {
        Reader kr(k), vr(v);
        uint32_t seq = kr.u32();
        Bytes hb = vr.bincode_bytes();
        uint32_t h = vr.u32();
        r.emplace_back(seq, std::make_pair(Hash32::from_span(hb), h));
        return true;
    });
    return r;
}
std::vector<std::pair<uint32_t, std::pair<Hash32, uint32_t>>> State::deposit_blocks(const Txn& t) const { return seq_table(t, T_DEPOSIT_BLOCKS); }
std::vector<std::pair<uint32_t, std::pair<Hash32, uint32_t>>> State::bundle_event_blocks(const Txn& t) const { return seq_table(t, T_BUNDLE_EVENT_BLOCKS); }

static Bytes enc_block_ref(const Hash32& h, uint32_t height)
{
    Writer w;
    w.bincode_bytes(h.span());
    w.u32(height);
    return w.buf;
}
static std::optional<std::pair<uint32_t, std::pair<Hash32, uint32_t>>> seq_last(const Txn& t, uint8_t table)
{
    auto l = t.last(table); // memcmp-largest key, exactly as LMDB's last()
    if (!l) return std::nullopt;
    Reader kr(l->first), vr(l->second);
    uint32_t seq = kr.u32();
    Bytes hb = vr.bincode_bytes();
    uint32_t h = vr.u32();
    return std::make_pair(seq, std::make_pair(Hash32::from_span(hb), h));
}

BlockIndexEvents State::block_index_events(const Txn& t, uint32_t h) const
{
    BlockIndexEvents ev;
    auto v = t.get(T_BLOCK_INDEX_EVENTS, u32le(h));
    if (!v) return ev;
    Reader r(*v);
    uint64_t n = r.u64();
    for (uint64_t i = 0; i < n; i++) {
        OutPoint op = de_outpoint(r);
        ev.deposits.emplace_back(op, de_filled_output(r));
    }
    uint64_t m = r.u64();
    for (uint64_t i = 0; i < m; i++) {
        OutPoint op = de_outpoint(r);
        Bytes id = r.bincode_bytes();
        ev.bundle_spends.emplace_back(op, Hash32::from_span(id));
    }
    return ev;
}

static Bytes enc_index_events(const BlockIndexEvents& ev)
{
    Writer w;
    w.u64(ev.deposits.size());
    for (auto& [op, o] : ev.deposits) {
        bincode(w, op);
        bincode(w, o);
    }
    w.u64(ev.bundle_spends.size());
    for (auto& [op, m] : ev.bundle_spends) {
        bincode(w, op);
        w.bincode_bytes(m.span());
    }
    return w.buf;
}

// mod.rs:636-677
uint64_t State::sidechain_wealth(const Txn& t) const
{
    uint64_t dep_utxo = 0, dep_stxo = 0, wd_stxo = 0;
    for (auto& [op, o] : utxos(t))
        if (op.kind == OutPoint::Deposit) {
            if (dep_utxo + o.get_value() < dep_utxo) throw StateError("AmountOverflow");
            dep_utxo += o.get_value();
        }
    for (auto& [op, s] : stxos(t)) {
        if (op.kind == OutPoint::Deposit) {
            if (dep_stxo + s.output.get_value() < dep_stxo) throw StateError("AmountOverflow");
            dep_stxo += s.output.get_value();
        }
        if (s.inpoint.kind == InPoint::Withdrawal) {
            if (wd_stxo + s.output.get_value() < wd_stxo) throw StateError("AmountOverflow");
            wd_stxo += s.output.get_value();
        }
    }
    uint64_t total = dep_utxo + dep_stxo;
    if (total < dep_utxo || total < wd_stxo) throw StateError("AmountOverflow");
    return total - wd_stxo;
}

// ------------------------------------------------------------------ BitNames tables
std::optional<BitNameRecord> State::bitname(const Txn& t, const Hash32& name) const
{
    auto v = t.get(T_BITNAMES, name.span());
    if (!v) return std::nullopt;
    return dec_record(*v);
}

void State::put_bitname(Txn& t, const Hash32& name, const BitNameRecord& r) const { t.put(T_BITNAMES, name.span(), enc_record(r)); }

std::vector<std::pair<Hash32, BitNameRecord>> State::bitnames(const Txn& t) const
{
    std::vector<std::pair<Hash32, BitNameRecord>> r;
    t.scan(T_BITNAMES, [&](ByteSpan k, ByteSpan v) {
        r.emplace_back(Hash32::from_span(k), dec_record(v));
        return true;
    });
    return r;
}

std::optional<Hash32> State::reservation(const Txn& t, const Hash32& txid) const
{
    auto v = t.get(T_RESERVATIONS, txid.span());
    if (!v) return std::nullopt;
    return Hash32::from_span(*v);
}

std::vector<std::pair<Hash32, Hash32>> State::reservations(const Txn& t) const
{
    std::vector<std::pair<Hash32, Hash32>> r;
    t.scan(T_RESERVATIONS, [&](ByteSpan k, ByteSpan v) {
        r.emplace_back(Hash32::from_span(k), Hash32::from_span(v));
        return true;
    });
    return r;
}

std::vector<std::pair<uint32_t, Hash32>> State::seq_to_bitname(const Txn& t) const
{
    std::vector<std::pair<uint32_t, Hash32>> r;
    t.scan(T_SEQ_TO_BITNAME, [&](ByteSpan k, ByteSpan v) {
        uint32_t s = uint32_t(k[0]) << 24 | uint32_t(k[1]) << 16 | uint32_t(k[2]) << 8 | k[3];
        r.emplace_back(s, Hash32::from_span(v));
        return true;
    });
    return r;
}

std::optional<BitNameData> State::bitname_at(const Txn& t, const Hash32& name, uint32_t h) const
{
    auto r = bitname(t, name);
    if (!r) return std::nullopt;
    return r->at_block_height(h);
}

// bitnames.rs:500-541
void State::apply_registration(Txn& t, const FilledTransaction& ft, uint32_t height) const
{
    const TxData& d = *ft.tx->data;
    auto implied = ft.tx->implied_reservation_commitment();
    if (!implied) throw StateError("NoReservationForRegistration");
    std::optional<Hash32> burned;
    for (auto& u : ft.spent_utxos)
        if (u.content.is_reservation() && u.content.reservation_commitment == *implied) {
            burned = u.content.reservation_txid;
            break;
        }
    if (!burned) throw StateError("NoReservationForRegistration");
    if (!t.del(T_RESERVATIONS, burned->span())) throw StateError("MissingReservation " + bt::hex_encode(*burned));
    uint32_t seq = 0;
    if (auto l = t.last(T_SEQ_TO_BITNAME)) seq = (uint32_t(l->first[0]) << 24 | uint32_t(l->first[1]) << 16 | uint32_t(l->first[2]) << 8 | l->first[3]) + 1;
    t.put(T_SEQ_TO_BITNAME, u32be(seq), d.name_hash.span());
    // overwrites an existing record for the same name (same-block duplicates, §5 #1)
    put_bitname(t, d.name_hash, BitNameRecord::init(d.data, ft.tx->txid(), height, seq));
}

// bitnames.rs:544-587
void State::revert_registration(Txn& t, const FilledTransaction& ft) const
{
    const Hash32& name = ft.tx->data->name_hash;
    auto rec = bitname(t, name);
    if (!rec) throw StateError("BitName Missing " + bt::hex_encode(name));
    if (!t.del(T_BITNAMES, name.span())) throw StateError("BitName Missing");
    auto l = t.last(T_SEQ_TO_BITNAME);
    if (!l) throw StateError("A registered bitname should have a seq id", true);
    if (Hash32::from_span(l->second) != name) throw StateError("assert_eq!(latest_registered_bitname, bitname)", true);
    if (!t.del(T_SEQ_TO_BITNAME, u32be(rec->seq_id))) throw StateError("BitName Missing");
    auto implied = ft.tx->implied_reservation_commitment();
    if (!implied) throw StateError("A BitName registration tx should have an implied commitment", true);
    std::optional<Hash32> burned;
    for (auto& u : ft.spent_utxos)
        if (u.content.is_reservation() && u.content.reservation_commitment == *implied) {
            burned = u.content.reservation_txid;
            break;
        }
    if (!burned) throw StateError("A BitName registration tx should correspond to a burned reservation", true);
    t.put(T_RESERVATIONS, burned->span(), implied->span());
}

static const Hash32* last_spent_bitname(const FilledTransaction& ft)
{
    for (auto it = ft.spent_utxos.rbegin(); it != ft.spent_utxos.rend(); ++it)
        if (it->content.is_bitname()) return &it->content.bitname;
    return nullptr;
}

void State::apply_updates(Txn& t, const FilledTransaction& ft, uint32_t height) const
{
    auto name = last_spent_bitname(ft);
    if (!name) throw StateError("NoBitNamesToUpdate");
    auto rec = bitname(t, *name);
    if (!rec) throw StateError("BitName Missing " + bt::hex_encode(*name));
    rec->apply_updates(ft.tx->data->updates, ft.tx->txid(), height);
    put_bitname(t, *name, *rec);
}

void State::revert_updates(Txn& t, const FilledTransaction& ft, uint32_t height) const
{
    auto name = last_spent_bitname(ft);
    if (!name) throw StateError("NoBitNamesToUpdate");
    auto rec = bitname(t, *name);
    if (!rec) throw StateError("BitName Missing " + bt::hex_encode(*name));
    rec->revert_updates(ft.tx->data->updates, ft.tx->txid(), height);
    put_bitname(t, *name, *rec);
}

// bitnames.rs:590-659 (unreachable on betanet: every BatchIcann fails validation)
void State::apply_batch_icann(Txn& t, const FilledTransaction& ft) const
{
    size_t k = 0;
    std::vector<size_t> bitname_inputs;
    for (size_t i = 0; i < ft.spent_utxos.size(); i++)
        if (ft.spent_utxos[i].content.is_bitname()) bitname_inputs.push_back(i);
    for (auto& plain : ft.tx->data->icann.plain_names) {
        Hash32 nh = name_hash(plain);
        bool found = false;
        while (k < bitname_inputs.size()) // Iterator::any consumes up to and including the match
            if (ft.spent_utxos[bitname_inputs[k++]].content.bitname == nh) {
                found = true;
                break;
            }
        if (!found) throw StateError("MissingBitNameInput");
        auto rec = bitname(t, nh);
        if (!rec) throw StateError("BitName Missing");
        if (rec->is_icann) throw StateError("AlreadyIcann");
        rec->is_icann = true;
        put_bitname(t, nh, *rec);
    }
}

void State::revert_batch_icann(Txn& t, const FilledTransaction& ft) const
{
    size_t k = 0;
    std::vector<size_t> bitname_inputs;
    for (size_t i = 0; i < ft.spent_utxos.size(); i++)
        if (ft.spent_utxos[i].content.is_bitname()) bitname_inputs.push_back(i);
    auto& names = ft.tx->data->icann.plain_names;
    for (auto it = names.rbegin(); it != names.rend(); ++it) {
        Hash32 nh = name_hash(*it);
        bool found = false;
        while (k < bitname_inputs.size())
            if (ft.spent_utxos[bitname_inputs[k++]].content.bitname == nh) {
                found = true;
                break;
            }
        if (!found) throw StateError("MissingBitNameInput");
        auto rec = bitname(t, nh);
        if (!rec) throw StateError("BitName Missing");
        if (rec->is_icann) throw StateError("assert!(!bitname_data.is_icann)", true); // SPEC #3: always panics
        rec->is_icann = false;
        put_bitname(t, nh, *rec);
    }
}

// ------------------------------------------------------------------ transactions (mod.rs:321-612)
FilledTransaction State::fill(const Txn& t, const Transaction& tx) const
{
    FilledTransaction ft{&tx, {}};
    for (auto& op : tx.inputs) {
        auto u = utxo(t, op);
        if (!u) throw StateError("NoUtxo " + op.to_string());
        ft.spent_utxos.push_back(*u);
    }
    return ft;
}

FilledTransaction State::fill_from_stxos(const Txn& t, const Transaction& tx) const
{
    FilledTransaction ft{&tx, {}};
    Hash32 txid = tx.txid();
    ft.spent_utxos.resize(tx.inputs.size());
    for (size_t vin = tx.inputs.size(); vin-- > 0;) {
        auto s = stxo(t, tx.inputs[vin]);
        if (!s) throw StateError("NoStxo " + tx.inputs[vin].to_string());
        if (!(s->inpoint == InPoint{InPoint::Regular, txid, uint32_t(vin)})) throw StateError("fill_transaction_from_stxos: inpoint mismatch", true);
        ft.spent_utxos[vin] = s->output;
    }
    return ft;
}

void State::validate_reservations(const FilledTransaction& ft)
{
    size_t in = 0, out = 0;
    for (auto& u : ft.spent_utxos)
        if (u.content.is_reservation()) in++;
    for (auto& o : ft.tx->outputs)
        if (o.content.kind == Content::BitNameReservation) out++;
    if (ft.tx->is_reservation()) {
        if (out == in + 1) return;
    } else if (ft.tx->is_registration()) {
        if (in == out + 1) return;
    } else if (in == out) {
        return;
    }
    throw StateError("UnbalancedReservations");
}

void State::validate_bitnames(const Txn& t, const FilledTransaction& ft) const
{
    size_t in = 0, out = 0;
    for (auto& u : ft.spent_utxos)
        if (u.content.is_bitname()) in++;
    for (auto& o : ft.tx->outputs)
        if (o.content.kind == Content::BitName) out++;
    if (ft.tx->is_update() && (in < 1 || out < 1)) throw StateError("NoBitNamesToUpdate");
    if (ft.tx->is_batch_icann() && out < ft.tx->data->icann.plain_names.size()) throw StateError("TooFewBitNameOutputs");
    if (ft.tx->is_registration()) {
        // the pre-block DB only: two registrations of one name in one block both pass (§5 #1)
        if (bitname(t, ft.tx->data->name_hash)) throw StateError("BitNameAlreadyRegistered");
        auto implied = ft.tx->implied_reservation_commitment();
        bool burns = false;
        for (auto& u : ft.spent_utxos)
            if (u.content.is_reservation() && u.content.reservation_commitment == *implied) burns = true;
        if (!burns) throw StateError("NoReservationForRegistration");
        if (out == in + 1) return;
    } else if (out == in) {
        return;
    }
    throw StateError("UnbalancedBitNames");
}

// mod.rs:504-549. BATCH_ICANN_VERIFYING_KEY is None (all-zero placeholder bytes are not a
// valid point), so every batch ICANN registration is invalid; the name checks before it
// fail the same way.
void State::validate_batch_icann(const FilledTransaction& ft)
{
    if (ft.tx->is_batch_icann()) throw StateError("InvalidBatchIcannRegistrationSignature");
}

uint64_t State::validate_filled(const Txn& t, const FilledTransaction& ft) const
{
    validate_reservations(ft);
    validate_bitnames(t, ft);
    validate_batch_icann(ft);
    for (size_t i = 0; i < ft.spent_utxos.size(); i++)
        if (ft.spent_utxos[i].content.is_withdrawal()) throw StateError("SpendWithdrawalOutput " + ft.tx->inputs[i].to_string());
    auto fee = ft.fee();
    if (!fee) throw StateError("ComputeFee");
    return *fee;
}

uint64_t State::validate_transaction(const Txn& t, const AuthorizedTransaction& tx) const
{
    FilledTransaction ft = fill(t, tx.transaction);
    auto required = ft.spent_utxos_requiring_auth();
    if (tx.authorizations.size() != required.size()) throw StateError("WrongNumberOfAuthorizations");
    for (size_t i = 0; i < tx.authorizations.size() && i < ft.spent_utxos.size(); i++)
        if (address_from_vk(tx.authorizations[i].verifying_key) != ft.spent_utxos[i].address) throw StateError("WrongPubKeyForAddress");
    if (!verify_authorized_transaction(tx)) throw StateError("AuthorizationError");
    return validate_filled(t, ft);
}

// ------------------------------------------------------------------ blocks (block.rs:127-243)
PrevalidatedBlock State::prevalidate(const Txn& t, const Header& h, const Body& body, CheckOpts opts) const
{
    if (borsh_bytes(body).size() > Body::MAX_SIZE) throw StateError("BodyTooLarge");
    if (h.prev_side_hash != tip(t)) throw StateError("InvalidHeader: PrevSideHash");
    uint64_t cb_value = 0;
    for (auto& o : body.coinbase.outputs) {
        if (cb_value + o.get_value() < cb_value) throw StateError("AmountOverflow");
        cb_value += o.get_value();
    }
    PrevalidatedBlock pre;
    for (auto& tx : body.transactions) pre.filled.push_back(fill(t, tx));
    std::vector<std::array<uint8_t, 37>> keys;
    for (auto& tx : body.transactions)
        for (auto& op : tx.inputs) keys.push_back(op.key());
    std::sort(keys.begin(), keys.end());
    for (size_t i = 1; i < keys.size(); i++)
        if (keys[i] == keys[i - 1]) throw StateError("UtxoDoubleSpent");
    uint64_t total_fees = 0;
    for (auto& ft : pre.filled) {
        uint64_t fee = validate_filled(t, ft);
        if (total_fees + fee < total_fees) throw StateError("AmountOverflow");
        total_fees += fee;
    }
    if (cb_value > total_fees) throw StateError("NotEnoughFees");
    auto mr = compute_merkle_root(body.coinbase, pre.filled);
    if (!mr) throw StateError("ComputeMerkleRoot", true);
    if (*mr != h.merkle_root) throw StateError("InvalidBody: merkle root");
    if (opts.authorizations) {
        size_t required = 0;
        std::vector<const FilledOutput*> needing;
        for (auto& ft : pre.filled) {
            auto r = ft.spent_utxos_requiring_auth();
            required += r.size();
        }
        if (body.authorizations.size() != required) throw StateError("WrongNumberOfAuthorizations");
        size_t k = 0;
        for (auto& ft : pre.filled)
            for (auto& u : ft.spent_utxos_requiring_auth()) {
                if (k >= body.authorizations.size()) break;
                if (address_from_vk(body.authorizations[k].verifying_key) != u.address) throw StateError("WrongPubKeyForAddress");
                k++;
            }
        if (!verify_authorizations(body)) throw StateError("AuthorizationError");
    }
    auto ht = height(t);
    pre.next_height = ht ? *ht + 1 : 0;
    pre.merkle_root = *mr;
    pre.total_fees = total_fees;
    pre.coinbase_value = cb_value;
    return pre;
}

// block.rs:246-364 connect_prevalidated: UTXO writes are collected in sorted maps and
// applied after all transactions (deletes, then STXOs, then new UTXOs); BitNames table
// writes happen in transaction order as they go.
void State::connect_prevalidated(Txn& t, const Header& h, const Body& body, const PrevalidatedBlock& pre) const
{
    uint32_t height = pre.next_height;
    std::map<std::array<uint8_t, 37>, bool> utxo_deletes;
    std::map<std::array<uint8_t, 37>, SpentOutput> stxo_puts;
    std::map<std::array<uint8_t, 37>, FilledOutput> utxo_puts;
    Hash32 cb_txid = h.coinbase_txid();
    for (uint32_t vout = 0; vout < body.coinbase.outputs.size(); vout++) {
        auto& o = body.coinbase.outputs[vout];
        FilledOutput f;
        f.address = o.address;
        f.memo = o.memo;
        if (o.content.kind == Content::Bitcoin) {
            f.content.kind = FilledContent::Bitcoin;
            f.content.value = o.content.value;
        } else if (o.content.kind == Content::Withdrawal) {
            f.content.kind = FilledContent::BitcoinWithdrawal;
            f.content.value = o.content.value;
            f.content.main_fee = o.content.main_fee;
            f.content.main_address = o.content.main_address;
        } else {
            throw StateError("BadCoinbaseOutputContent"); // only checked at connect (§5 #4)
        }
        utxo_puts[OutPoint{OutPoint::Coinbase, cb_txid, vout}.key()] = f;
    }
    for (size_t i = 0; i < body.transactions.size(); i++) {
        const Transaction& tx = body.transactions[i];
        const FilledTransaction& ft = pre.filled.at(i);
        Hash32 txid = tx.txid();
        for (uint32_t vin = 0; vin < tx.inputs.size(); vin++) {
            auto key = tx.inputs[vin].key();
            auto u = utxo(t, tx.inputs[vin]);
            if (!u) throw StateError("NoUtxo " + tx.inputs[vin].to_string());
            utxo_deletes[key] = true;
            stxo_puts[key] = SpentOutput{*u, InPoint{InPoint::Regular, txid, vin}};
        }
        auto outs = ft.filled_outputs();
        if (!outs) throw StateError("FillTxOutputContentsFailed");
        for (uint32_t vout = 0; vout < outs->size(); vout++) utxo_puts[OutPoint{OutPoint::Regular, txid, vout}.key()] = (*outs)[vout];
        if (tx.data) {
            switch (tx.data->kind) {
            case TxData::Reservation: t.put(T_RESERVATIONS, txid.span(), tx.data->commitment.span()); break;
            case TxData::Registration: apply_registration(t, ft, height); break;
            case TxData::Update: apply_updates(t, ft, height); break;
            case TxData::BatchIcann: apply_batch_icann(t, ft); break;
            }
        }
    }
    for (auto& [k, _] : utxo_deletes) t.del(T_UTXOS, ByteSpan(k.data(), k.size()));
    for (auto& [k, s] : stxo_puts) {
        Writer w;
        enc_spent(w, s);
        t.put(T_STXOS, ByteSpan(k.data(), k.size()), w.buf);
    }
    for (auto& [k, o] : utxo_puts) {
        Writer w;
        bincode(w, o);
        t.put(T_UTXOS, ByteSpan(k.data(), k.size()), w.buf);
    }
    t.put(T_TIP, UNIT, h.hash().span());
    t.put(T_HEIGHT, UNIT, u32le(height));
}

// block.rs:450-560
void State::disconnect_tip(Txn& t, const Header& h, const Body& body) const
{
    auto tip_hash = tip(t);
    if (!tip_hash) throw StateError("NoTip");
    if (*tip_hash != h.hash()) throw StateError("InvalidHeader: BlockHash");
    auto ht = height(t);
    if (!ht) throw StateError("Height should not be None", true);
    uint32_t height_ = *ht;
    std::vector<FilledTransaction> filled(body.transactions.size());
    for (size_t i = body.transactions.size(); i-- > 0;) {
        const Transaction& tx = body.transactions[i];
        Hash32 txid = tx.txid();
        filled[i] = fill_from_stxos(t, tx);
        const FilledTransaction& ft = filled[i];
        if (tx.data) {
            switch (tx.data->kind) {
            case TxData::Reservation:
                if (!t.del(T_RESERVATIONS, txid.span())) throw StateError("MissingReservation " + bt::hex_encode(txid));
                break;
            case TxData::Registration: revert_registration(t, ft); break;
            case TxData::Update: revert_updates(t, ft, height_); break;
            case TxData::BatchIcann: revert_batch_icann(t, ft); break;
            }
        }
        for (int64_t vout = int64_t(tx.outputs.size()) - 1; vout >= 0; vout--) {
            OutPoint op{OutPoint::Regular, txid, uint32_t(vout)};
            auto k = op.key();
            if (!t.del(T_UTXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoUtxo " + op.to_string());
        }
        for (auto in = tx.inputs.rbegin(); in != tx.inputs.rend(); ++in) {
            auto s = stxo(t, *in);
            if (!s) throw StateError("NoStxo " + in->to_string());
            auto k = in->key();
            t.del(T_STXOS, ByteSpan(k.data(), k.size()));
            put_utxo(t, *in, s->output);
        }
    }
    Hash32 cb_txid = h.coinbase_txid();
    for (int64_t vout = int64_t(body.coinbase.outputs.size()) - 1; vout >= 0; vout--) {
        OutPoint op{OutPoint::Coinbase, cb_txid, uint32_t(vout)};
        auto k = op.key();
        if (!t.del(T_UTXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoUtxo " + op.to_string());
    }
    auto mr = compute_merkle_root(body.coinbase, filled);
    if (!mr) throw StateError("ComputeMerkleRoot", true);
    if (*mr != h.merkle_root) throw StateError("InvalidBody: merkle root");
    if (!h.prev_side_hash && height_ == 0) {
        t.del(T_TIP, UNIT);
        t.del(T_HEIGHT, UNIT);
    } else if (!h.prev_side_hash || height_ == 0) {
        throw StateError("NoTip");
    } else {
        t.put(T_TIP, UNIT, h.prev_side_hash->span());
        t.put(T_HEIGHT, UNIT, u32le(height_ - 1));
    }
}

// ------------------------------------------------------------------ two-way peg
// lib/types/proto.rs:447-517
FilledOutput State::deposit_output(const bt::mainchain::Deposit& d)
{
    FilledOutput o;
    o.content.kind = FilledContent::Bitcoin;
    o.content.value = d.value_sats;
    o.address = Address::ALL_ZEROS;
    std::string s(d.address.begin(), d.address.end());
    if (Reader::utf8_valid(s)) {
        if (auto a = Address::from_deposit_address(s)) o.address = *a;
        else if (auto b = Address::from_base58(s)) o.address = *b;
    }
    return o;
}

// two_way_peg_data.rs:24-117
std::optional<WithdrawalBundle> State::collect_withdrawal_bundle(const Txn& t, uint32_t block_height) const
{
    struct Agg {
        bt::btc::Address addr;
        uint64_t value = 0, main_fee = 0;
        std::map<OutPoint, FilledOutput> utxos;
    };
    std::vector<Agg> aggs; // HashMap keyed by Address (Eq includes network/hrp)
    for (auto& [op, o] : utxos(t)) {
        if (!o.content.is_withdrawal()) continue;
        auto it = std::find_if(aggs.begin(), aggs.end(), [&](const Agg& a) { return a.addr == o.content.main_address; });
        if (it == aggs.end()) {
            aggs.push_back(Agg{o.content.main_address, 0, 0, {}});
            it = std::prev(aggs.end());
        }
        if (it->value + o.content.value < it->value) throw StateError("AmountOverflow");
        it->value += o.content.value;
        if (it->main_fee + o.content.main_fee < it->main_fee) throw StateError("AmountOverflow");
        it->main_fee += o.content.main_fee;
        it->utxos[op] = o;
    }
    if (aggs.empty()) return std::nullopt;
    std::sort(aggs.begin(), aggs.end(), [](const Agg& a, const Agg& b) { // Reverse((main_fee, value, main_address))
        if (a.main_fee != b.main_fee) return a.main_fee > b.main_fee;
        if (a.value != b.value) return a.value > b.value;
        return b.addr < a.addr;
    });
    uint64_t fee = 0;
    std::map<OutPoint, FilledOutput> spend;
    std::vector<bt::btc::TxOut> outs;
    uint32_t txouts_size = 0;
    for (auto& a : aggs) {
        Bytes spk = a.addr.script_pubkey();
        uint64_t n_outputs = outs.size() + 1;
        if (n_outputs > UINT32_MAX) break;
        if (spk.size() > UINT32_MAX) continue;
        auto ts = txout_size(uint32_t(spk.size()));
        if (!ts) continue;
        uint64_t sum = uint64_t(txouts_size) + *ts;
        if (sum > UINT32_MAX) break;
        txouts_size = uint32_t(sum);
        if (!predict_weight_ok(uint32_t(n_outputs), txouts_size)) break; // `break`, not skip
        for (auto& [op, o] : a.utxos) spend[op] = o;
        outs.push_back({a.value, spk});
        if (fee + a.main_fee < fee) throw StateError("Amount addition overflow", true); // `+=` panics
        fee += a.main_fee;
    }
    auto b = make_withdrawal_bundle(block_height, fee, std::move(spend), std::move(outs));
    if (!b) throw StateError("BundleTooHeavy");
    return b;
}

// two_way_peg_data.rs:119-267
void State::connect_bundle_submitted(Txn& t, uint32_t block_height, BlockIndexEvents& ev, const Hash32& m6id) const
{
    auto pending = pending_bundle_m6id(t);
    if (pending && *pending == m6id) {
        auto b = bundle(t, m6id);
        if (!b || b->first.kind != WithdrawalBundleInfo::Known) throw StateError("PendingWithdrawalBundleUnknown");
        for (auto& [op, o] : b->first.bundle.spend_utxos) {
            auto k = op.key();
            if (!t.del(T_UTXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoUtxo " + op.to_string());
            put_stxo(t, op, SpentOutput{o, InPoint{InPoint::Withdrawal, m6id, 0}});
            ev.bundle_spends.emplace_back(op, m6id);
        }
        if (b->second.latest().value != BundleStatus::Pending) throw StateError("assert Pending", true);
        if (!b->second.push(BundleStatus::Submitted, block_height)) throw StateError("push submitted", true);
        put_bundle(t, m6id, b->first, b->second);
        t.del(T_PENDING_BUNDLE, UNIT);
        return;
    }
    if (auto b = bundle(t, m6id)) {
        auto st = b->second.latest().value;
        auto kind = b->first.kind;
        if (st == BundleStatus::Confirmed) throw StateError("ConfirmedResubmitted");
        if (st == BundleStatus::Submitted || st == BundleStatus::SubmittedUnexpected) throw StateError("Resubmitted");
        if (st == BundleStatus::Dropped) {
            if (kind != WithdrawalBundleInfo::Known) throw StateError("UnknownDropped");
        } else if (st == BundleStatus::Pending) {
            if (kind == WithdrawalBundleInfo::Known) throw StateError("DroppedPending");
            throw StateError("UnknownPending");
        } else if (st == BundleStatus::Failed) {
            if (kind == WithdrawalBundleInfo::UnknownConfirmed) throw StateError("UnknownConfirmedFailed");
        }
        if (!b->second.push(BundleStatus::SubmittedUnexpected, block_height)) throw StateError("push submitted unexpected", true);
        put_bundle(t, m6id, b->first, b->second);
        return;
    }
    WithdrawalBundleInfo info;
    info.kind = WithdrawalBundleInfo::Unknown;
    put_bundle(t, m6id, info, RollBack<BundleStatus>::make(BundleStatus::Submitted, block_height));
}

// two_way_peg_data.rs:269-386
void State::connect_bundle_confirmed(Txn& t, uint32_t block_height, const Hash32& m6id) const
{
    auto b = bundle(t, m6id);
    if (!b) throw StateError("UnknownWithdrawalBundle");
    auto& [info, st] = *b;
    if (st.latest().value == BundleStatus::Confirmed) return;
    if (st.latest().value != BundleStatus::Submitted && st.latest().value != BundleStatus::SubmittedUnexpected) throw StateError("assert Submitted", true);
    if (info.kind == WithdrawalBundleInfo::UnknownConfirmed) throw StateError("UnknownWithdrawalBundleReconfirmed");
    if (info.kind == WithdrawalBundleInfo::Unknown) {
        if (block_height != 0) throw StateError("UnknownWithdrawalBundleConfirmed"); // halts the chain
        std::map<OutPoint, FilledOutput> all;
        for (auto& [op, o] : utxos(t)) all[op] = o;
        for (auto& [op, o] : all) put_stxo(t, op, SpentOutput{o, InPoint{InPoint::Withdrawal, m6id, 0}});
        t.clear(T_UTXOS);
        info.kind = WithdrawalBundleInfo::UnknownConfirmed;
        info.spend_utxos = std::move(all);
    } else if (info.kind == WithdrawalBundleInfo::Known && st.latest().value == BundleStatus::SubmittedUnexpected) {
        for (auto& [op, o] : info.bundle.spend_utxos) {
            auto k = op.key();
            if (!t.del(T_UTXOS, ByteSpan(k.data(), k.size()))) throw StateError("UnexpectedWithdrawalBundleInsolvency");
            put_stxo(t, op, SpentOutput{o, InPoint{InPoint::Withdrawal, m6id, 0}});
        }
    }
    if (!st.push(BundleStatus::Confirmed, block_height)) throw StateError("push confirmed", true);
    put_bundle(t, m6id, info, st);
}

// two_way_peg_data.rs:388-447
void State::connect_bundle_failed(Txn& t, uint32_t block_height, const Hash32& m6id) const
{
    auto b = bundle(t, m6id);
    if (!b) throw StateError("UnknownWithdrawalBundle");
    auto& [info, st] = *b;
    if (st.latest().value == BundleStatus::Failed) return;
    if (st.latest().value != BundleStatus::Submitted && st.latest().value != BundleStatus::SubmittedUnexpected) throw StateError("assert Submitted", true);
    if (info.kind == WithdrawalBundleInfo::Known && st.latest().value != BundleStatus::SubmittedUnexpected) {
        for (auto& [op, o] : info.bundle.spend_utxos) {
            auto k = op.key();
            t.del(T_STXOS, ByteSpan(k.data(), k.size()));
            put_utxo(t, op, o);
        }
        auto lf = latest_failed_rollback(t);
        RollBack<Hash32> nl;
        if (lf) {
            nl = *lf;
            if (!nl.push(m6id, block_height)) throw StateError("push latest failed", true);
        } else {
            nl = RollBack<Hash32>::make(m6id, block_height);
        }
        put_latest_failed(t, nl);
    }
    if (!st.push(BundleStatus::Failed, block_height)) throw StateError("push failed", true);
    put_bundle(t, m6id, info, st);
}

// two_way_peg_data.rs:540-622
void State::connect_2wpd(Txn& t, const TwoWayPegData& d) const
{
    auto ht = height(t);
    if (!ht) throw StateError("NoTip");
    uint32_t block_height = *ht;
    BlockIndexEvents ev;
    std::optional<Hash32> latest_deposit_block, latest_bundle_event_block;
    for (auto& [event_block, bi] : d.block_info) {
        for (auto& e : bi.events) {
            if (auto dep = std::get_if<bt::mainchain::Deposit>(&e)) {
                OutPoint op{OutPoint::Deposit, dep->txid, dep->vout};
                FilledOutput o = deposit_output(*dep);
                put_utxo(t, op, o);
                ev.deposits.emplace_back(op, o);
                latest_deposit_block = event_block;
            } else {
                auto& we = std::get<bt::mainchain::WithdrawalBundleEvent>(e);
                switch (we.status) {
                case bt::mainchain::BundleStatus::Submitted: connect_bundle_submitted(t, block_height, ev, we.m6id); break;
                case bt::mainchain::BundleStatus::Confirmed: connect_bundle_confirmed(t, block_height, we.m6id); break;
                case bt::mainchain::BundleStatus::Failed: connect_bundle_failed(t, block_height, we.m6id); break;
                }
                latest_bundle_event_block = event_block;
            }
        }
    }
    if (!ev.empty()) t.put(T_BLOCK_INDEX_EVENTS, u32le(block_height), enc_index_events(ev));
    if (latest_deposit_block) {
        auto l = seq_last(t, T_DEPOSIT_BLOCKS);
        uint32_t seq = l ? l->first + 1 : 0;
        t.put(T_DEPOSIT_BLOCKS, u32le(seq), enc_block_ref(*latest_deposit_block, block_height));
    }
    if (latest_bundle_event_block) {
        auto l = seq_last(t, T_BUNDLE_EVENT_BLOCKS);
        uint32_t seq = l ? l->first + 1 : 0;
        t.put(T_BUNDLE_EVENT_BLOCKS, u32le(seq), enc_block_ref(*latest_bundle_event_block, block_height));
    }
    auto lf = latest_failed_bundle(t);
    uint32_t last_failure_height = lf ? lf->first : 0;
    if (uint32_t(block_height - last_failure_height) >= WITHDRAWAL_BUNDLE_FAILURE_GAP && !pending_bundle_m6id(t)) {
        if (auto bundle_ = collect_withdrawal_bundle(t, block_height)) {
            Hash32 m6id = bundle_->m6id();
            t.put(T_PENDING_BUNDLE, UNIT, m6id.span());
            RollBack<BundleStatus> st;
            if (auto existing = bundle(t, m6id)) {
                st = existing->second;
                if (!st.push(BundleStatus::Pending, block_height)) throw StateError("push pending", true);
            } else {
                st = RollBack<BundleStatus>::make(BundleStatus::Pending, block_height);
            }
            WithdrawalBundleInfo info;
            info.kind = WithdrawalBundleInfo::Known;
            info.bundle = std::move(*bundle_);
            put_bundle(t, m6id, info, st);
        }
    }
}

// two_way_peg_data.rs:624-688
void State::disconnect_bundle_submitted(Txn& t, uint32_t block_height, const Hash32& m6id) const
{
    auto b = bundle(t, m6id);
    if (!b) {
        auto p = pending_bundle_m6id(t);
        if (p && *p == m6id) return;
        throw StateError("UnknownWithdrawalBundle");
    }
    auto [rest, latest] = b->second.pop();
    if (latest.value != BundleStatus::Submitted && latest.value != BundleStatus::SubmittedUnexpected) throw StateError("assert", true);
    if (latest.height != block_height) throw StateError("assert height", true);
    if (b->first.kind == WithdrawalBundleInfo::Known && rest && rest->latest().value == BundleStatus::Pending) {
        auto& su = b->first.bundle.spend_utxos;
        for (auto it = su.rbegin(); it != su.rend(); ++it) {
            auto k = it->first.key();
            if (!t.del(T_STXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoStxo");
            put_utxo(t, it->first, it->second);
        }
        t.put(T_PENDING_BUNDLE, UNIT, m6id.span());
    }
    if (rest) put_bundle(t, m6id, b->first, *rest);
    else t.del(T_BUNDLES, m6id_key(m6id));
}

// two_way_peg_data.rs:690-758
void State::disconnect_bundle_confirmed(Txn& t, uint32_t block_height, const Hash32& m6id) const
{
    auto b = bundle(t, m6id);
    if (!b) throw StateError("UnknownWithdrawalBundle");
    auto info = b->first;
    auto [prev, latest] = b->second.pop();
    if (latest.value == BundleStatus::Submitted || latest.value == BundleStatus::SubmittedUnexpected) return;
    if (latest.value != BundleStatus::Confirmed) throw StateError("assert Confirmed", true);
    if (latest.height != block_height) throw StateError("assert height", true);
    if (!prev) throw StateError("Pop confirmed bundle status should be valid", true);
    auto pst = prev->latest().value;
    if (pst != BundleStatus::Submitted && pst != BundleStatus::SubmittedUnexpected) throw StateError("assert", true);
    if (info.kind == WithdrawalBundleInfo::Known) {
        if (pst == BundleStatus::SubmittedUnexpected)
            for (auto& [op, o] : info.bundle.spend_utxos) {
                put_utxo(t, op, o);
                auto k = op.key();
                if (!t.del(T_STXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoStxo");
            }
    } else if (info.kind == WithdrawalBundleInfo::UnknownConfirmed) {
        for (auto& [op, o] : info.spend_utxos) {
            put_utxo(t, op, o);
            auto k = op.key();
            if (!t.del(T_STXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoStxo");
        }
        info.kind = WithdrawalBundleInfo::Unknown;
        info.spend_utxos.clear();
    }
    put_bundle(t, m6id, info, *prev);
}

// two_way_peg_data.rs:760-835
void State::disconnect_bundle_failed(Txn& t, uint32_t block_height, const Hash32& m6id) const
{
    auto b = bundle(t, m6id);
    if (!b) throw StateError("UnknownWithdrawalBundle");
    auto [prev, latest] = b->second.pop();
    if (latest.value == BundleStatus::Submitted) return;
    if (latest.value != BundleStatus::Failed) throw StateError("assert Failed", true);
    if (latest.height != block_height) throw StateError("assert height", true);
    if (!prev) throw StateError("Pop failed bundle status should be valid", true);
    auto pst = prev->latest().value;
    if (pst != BundleStatus::Submitted && pst != BundleStatus::SubmittedUnexpected) throw StateError("assert", true);
    if (b->first.kind == WithdrawalBundleInfo::Known && pst != BundleStatus::SubmittedUnexpected) {
        auto& su = b->first.bundle.spend_utxos;
        for (auto it = su.rbegin(); it != su.rend(); ++it) {
            put_stxo(t, it->first, SpentOutput{it->second, InPoint{InPoint::Withdrawal, m6id, 0}});
            auto k = it->first.key();
            if (!t.del(T_UTXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoUtxo");
        }
        auto lf = latest_failed_rollback(t);
        if (!lf) throw StateError("latest failed withdrawal bundle should exist", true);
        auto [prest, platest] = lf->pop();
        if (platest.value != m6id || platest.height != block_height) throw StateError("assert latest failed", true);
        if (prest) put_latest_failed(t, *prest);
        else t.del(T_LATEST_FAILED, UNIT);
    }
    put_bundle(t, m6id, b->first, *prev);
}

// two_way_peg_data.rs:928-1022
void State::disconnect_2wpd(Txn& t, const TwoWayPegData& d) const
{
    auto ht = height(t);
    if (!ht) throw StateError("Height should not be None", true);
    uint32_t block_height = *ht;
    std::optional<Hash32> latest_deposit_block, latest_bundle_event_block;
    t.del(T_BLOCK_INDEX_EVENTS, u32le(block_height));
    for (auto bit = d.block_info.rbegin(); bit != d.block_info.rend(); ++bit) {
        auto& [event_block, bi] = *bit;
        for (auto eit = bi.events.rbegin(); eit != bi.events.rend(); ++eit) {
            if (auto dep = std::get_if<bt::mainchain::Deposit>(&*eit)) {
                OutPoint op{OutPoint::Deposit, dep->txid, dep->vout};
                auto k = op.key();
                if (!t.del(T_UTXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoUtxo " + op.to_string());
                if (!latest_deposit_block) latest_deposit_block = event_block;
            } else {
                auto& we = std::get<bt::mainchain::WithdrawalBundleEvent>(*eit);
                switch (we.status) {
                case bt::mainchain::BundleStatus::Submitted: disconnect_bundle_submitted(t, block_height, we.m6id); break;
                case bt::mainchain::BundleStatus::Confirmed: disconnect_bundle_confirmed(t, block_height, we.m6id); break;
                case bt::mainchain::BundleStatus::Failed: disconnect_bundle_failed(t, block_height, we.m6id); break;
                }
                if (!latest_bundle_event_block) latest_bundle_event_block = event_block;
            }
        }
    }
    if (latest_bundle_event_block) {
        auto l = seq_last(t, T_BUNDLE_EVENT_BLOCKS);
        if (!l) throw StateError("NoWithdrawalBundleEventBlock");
        if (l->second.first != *latest_bundle_event_block || l->second.second != block_height) throw StateError("assert bundle event block", true);
        if (!t.del(T_BUNDLE_EVENT_BLOCKS, u32le(l->first))) throw StateError("NoWithdrawalBundleEventBlock");
    }
    auto lf = latest_failed_bundle(t);
    uint32_t last_failure_height = lf ? lf->first : 0;
    if (uint32_t(block_height - last_failure_height) >= WITHDRAWAL_BUNDLE_FAILURE_GAP) {
        if (auto p = pending_bundle_m6id(t)) {
            auto b = bundle(t, *p);
            if (!b) throw StateError("PendingWithdrawalBundleUnknown");
            if (b->second.latest().height == block_height) {
                t.del(T_PENDING_BUNDLE, UNIT);
                auto [rest, _] = b->second.pop();
                if (rest) put_bundle(t, *p, b->first, *rest);
                else t.del(T_BUNDLES, m6id_key(*p));
            }
        }
    }
    if (latest_deposit_block) {
        auto l = seq_last(t, T_DEPOSIT_BLOCKS);
        if (!l) throw StateError("NoDepositBlock");
        if (l->second.first != *latest_deposit_block || l->second.second != block_height) throw StateError("assert deposit block", true);
        if (!t.del(T_DEPOSIT_BLOCKS, u32le(l->first))) throw StateError("NoDepositBlock");
    }
}

void mempool_check_inputs(const std::map<std::array<uint8_t, 37>, Hash32>& spent, const Transaction& tx)
{
    std::set<std::array<uint8_t, 37>> own;
    for (auto& op : tx.inputs) {
        auto k = op.key();
        if (spent.count(k) || !own.insert(k).second) throw StateError("UtxoDoubleSpent");
    }
}

} // namespace bitnames
