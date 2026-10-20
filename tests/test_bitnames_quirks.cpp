// Consensus quirks of the plain-bitnames fork v0.18.2 that a compatible node must
// reproduce exactly (study Part II BitNames §5, SPEC-bitnames [BUG] items): each test builds
// the construct, connects it with every check on, and asserts their outcome.
#include "test.h"

#include <bitnames/state.h>

#include <bt/crypto.h>

#include <cstring>
#include <deque>

using namespace bitnames;

namespace {

bt::frost::SigningKey key(uint8_t seed)
{
    bt::ByteArray<64> wide;
    for (int i = 0; i < 64; i++) wide[i] = uint8_t(seed * 31 + i);
    return bt::frost::SigningKey{bt::frost::reduce_wide(wide)};
}

Address addr_of(const bt::frost::SigningKey& k) { return address_from_vk(k.verifying_key()); }

Hash32 main_hash(uint32_t n)
{
    Hash32 h;
    h[0] = uint8_t(n);
    h[1] = uint8_t(n >> 8);
    h[31] = 0x77;
    return h;
}

struct Chain {
    bt::kv::MemStore store;
    State st;
    std::optional<Hash32> tip;
    uint32_t main = 1;

    /** Build a block on the tip; nullopt-merkle means "compute it". Throws StateError. */
    Header make_header(const Body& b)
    {
        bt::kv::Txn t(store);
        std::vector<FilledTransaction> filled;
        for (auto& tx : b.transactions) filled.push_back(st.fill(t, tx));
        Header h;
        h.merkle_root = *compute_merkle_root(b.coinbase, filled);
        h.prev_side_hash = tip;
        h.prev_main_hash = main_hash(main);
        return h;
    }
    void connect(const Header& h, const Body& b, const bt::mainchain::TwoWayPegData& d = {})
    {
        bt::kv::Txn t(store);
        auto pre = st.prevalidate(t, h, b);
        st.connect_prevalidated(t, h, b, pre);
        st.connect_2wpd(t, d);
        t.commit();
        tip = h.hash();
        main++;
    }
    Header add(const Body& b, const bt::mainchain::TwoWayPegData& d = {})
    {
        Header h = make_header(b);
        connect(h, b, d);
        return h;
    }
    void disconnect(const Header& h, const Body& b, const bt::mainchain::TwoWayPegData& d = {})
    {
        bt::kv::Txn t(store);
        st.disconnect_2wpd(t, d);
        st.disconnect_tip(t, h, b);
        t.commit();
        tip = h.prev_side_hash;
    }
};

bt::mainchain::TwoWayPegData deposit(const Address& to, uint64_t value, uint8_t n)
{
    bt::mainchain::Deposit d;
    d.txid[0] = n;
    d.txid[1] = 0xd0;
    d.vout = 0;
    std::string a = to.to_base58();
    d.address.assign(a.begin(), a.end());
    d.value_sats = value;
    bt::mainchain::BlockInfo bi;
    bi.events.push_back(d);
    bt::mainchain::TwoWayPegData w;
    w.block_info.emplace_back(main_hash(1000 + n), bi);
    return w;
}

Transaction reservation_tx(const Address& to, const Hash32& commitment, Bytes memo = {})
{
    Transaction t;
    Output o;
    o.address = to;
    o.content.kind = Content::BitNameReservation;
    t.outputs.push_back(o);
    t.memo = std::move(memo);
    TxData d;
    d.kind = TxData::Reservation;
    d.commitment = commitment;
    t.data = d;
    return t;
}

Hash32 commit_for(const Hash32& nonce, const Hash32& name)
{
    bt::Blake3 h(nonce);
    h.update(name.span());
    return h.finalize();
}

AuthorizedTransaction sign(const Transaction& t, const std::vector<bt::frost::SigningKey>& keys)
{
    AuthorizedTransaction at;
    at.transaction = t;
    Bytes msg = tx_signing_message(t);
    for (auto& k : keys) at.authorizations.push_back(Authorization{k.verifying_key(), k.sign(msg)});
    return at;
}

} // namespace

TEST(quirk_duplicate_registration_in_one_block)
{
    // §5 #1: validate_bitnames checks the pre-block DB only; two registrations of one name in
    // one block are accepted, the second overwrites the record, both tokens exist, the
    // first seq id is orphaned, and the block can no longer be disconnected.
    Chain c;
    auto k1 = key(1), k2 = key(2);
    Hash32 name = name_hash("dup");
    Hash32 n1, n2;
    n1.v.fill(1);
    n2.v.fill(2);
    Transaction r1 = reservation_tx(addr_of(k1), commit_for(n1, name)), r2 = reservation_tx(addr_of(k2), commit_for(n2, name), {1});
    Body b0;
    b0.transactions = {r1, r2};
    c.add(b0);
    auto reg = [&](const Transaction& res, const Hash32& nonce, const bt::frost::SigningKey& k, uint64_t fee_marker) {
        Transaction t;
        t.inputs.push_back(OutPoint{OutPoint::Regular, res.txid(), 0});
        Output o;
        o.address = addr_of(k);
        o.content.kind = Content::BitName;
        t.outputs.push_back(o);
        TxData d;
        d.kind = TxData::Registration;
        d.name_hash = name;
        d.revealed_nonce = nonce;
        d.data.paymail_fee_sats = fee_marker;
        t.data = d;
        return sign(t, {k});
    };
    auto a1 = reg(r1, n1, k1, 1), a2 = reg(r2, n2, k2, 2);
    Body b1 = Body::from_authorized({a1, a2}, {});
    Header h1 = c.add(b1);
    bt::kv::Txn t(c.store);
    auto rec = c.st.bitname(t, name);
    REQUIRE(rec.has_value());
    CHECK_EQ(rec->seq_id, 1u);                               // the second registration's seq
    CHECK(rec->current().data.paymail_fee_sats == std::optional<uint64_t>(2)); // overwritten
    CHECK_EQ(c.st.seq_to_bitname(t).size(), size_t(2));     // seq 0 orphaned, still mapped
    size_t tokens = 0;
    for (auto& [op, o] : c.st.utxos(t))
        if (o.content.is_bitname() && o.content.bitname == name) tokens++;
    CHECK_EQ(tokens, size_t(2));
    // disconnect reverts the second registration, then finds the name gone for the first
    bool failed = false;
    try {
        c.disconnect(h1, b1);
    } catch (const StateError& e) {
        failed = std::string(e.what()).find("Missing") != std::string::npos;
    }
    CHECK(failed);
    // a later block registering the same name again is rejected (name exists)
    Chain c2;
    c2.add(b0);
    Body only1 = Body::from_authorized({a1}, {});
    c2.add(only1);
    bool rejected = false;
    try {
        c2.add(Body::from_authorized({a2}, {}));
    } catch (const StateError& e) {
        rejected = std::string(e.what()) == "BitNameAlreadyRegistered";
    }
    CHECK(rejected);
}

TEST(quirk_zero_input_tx_replay)
{
    // §5 #2: zero-input transactions need no signature and replay with the same txid in a
    // later block (betanet: 37 txids, one confirmed 105 times); the replay overwrites the
    // UTXO and reservation entry, and disconnecting it deletes the original's entries, so the
    // original block can no longer be disconnected (MissingReservation).
    Chain c;
    Hash32 commitment;
    commitment.v.fill(9);
    Transaction r = reservation_tx(addr_of(key(3)), commitment);
    Body b;
    b.transactions = {r};
    Header h0 = c.add(b);
    Header h1 = c.add(b); // the same body, byte for byte, in the next block
    {
        bt::kv::Txn t(c.store);
        CHECK(c.st.utxo(t, OutPoint{OutPoint::Regular, r.txid(), 0}).has_value());
        CHECK(c.st.reservation(t, r.txid()) == std::optional<Hash32>(commitment));
        CHECK_EQ(*c.st.height(t), 1u);
    }
    c.disconnect(h1, b);
    {
        bt::kv::Txn t(c.store);
        CHECK(!c.st.utxo(t, OutPoint{OutPoint::Regular, r.txid(), 0}).has_value()); // the original's UTXO went too
        CHECK(!c.st.reservation(t, r.txid()).has_value());
    }
    bool failed = false;
    try {
        c.disconnect(h0, b);
    } catch (const StateError& e) {
        failed = std::string(e.what()).rfind("MissingReservation", 0) == 0;
    }
    CHECK(failed);
}

TEST(quirk_merkle_switch_at_1000_txs)
{
    // §5 #3: below 1000 transactions the tx root is a CKB CBMT; from 1000 it is a
    // duplicate-last levelized tree. Both give different roots for the same leaves.
    std::vector<Transaction> txs;
    for (uint32_t i = 0; i < 1000; i++) {
        Hash32 c;
        c[0] = uint8_t(i);
        c[1] = uint8_t(i >> 8);
        txs.push_back(reservation_tx(Address::ALL_ZEROS, c));
    }
    std::vector<FilledTransaction> f999, f1000;
    for (size_t i = 0; i < 999; i++) f999.push_back(FilledTransaction{&txs[i], {}});
    for (size_t i = 0; i < 1000; i++) f1000.push_back(FilledTransaction{&txs[i], {}});
    // a 1000-tx block connects with the levelized root
    Chain c;
    Body b;
    b.transactions = txs;
    Header h = c.make_header(b);
    CHECK(h.merkle_root == *compute_merkle_root({}, f1000));
    c.connect(h, b);
    // a 999-tx block takes the CBMT root (the < 1000 path)
    Chain c9;
    Body b9;
    b9.transactions.assign(txs.begin(), txs.begin() + 999);
    Header h9 = c9.make_header(b9);
    CHECK(h9.merkle_root == *compute_merkle_root({}, f999));
    c9.connect(h9, b9);
    // a wrong root is rejected
    Chain c2;
    Header bad = c2.make_header(b);
    bad.merkle_root[0] ^= 1;
    bool rejected = false;
    try {
        c2.connect(bad, b);
    } catch (const StateError& e) {
        rejected = std::string(e.what()).find("InvalidBody") == 0;
    }
    CHECK(rejected);
}

TEST(quirk_merkle_levelized_differs_from_cbmt)
{
    // The two constructions disagree whenever the count is not a power of two: compute
    // both directly from the same leaves (CBMT via the < 1000 path on a 1000-element
    // reference implemented here).
    std::vector<Transaction> txs;
    for (uint32_t i = 0; i < 1001; i++) {
        Hash32 c;
        c[0] = uint8_t(i);
        c[1] = uint8_t(i >> 8);
        c[2] = 0x55;
        txs.push_back(reservation_tx(Address::ALL_ZEROS, c));
    }
    std::vector<FilledTransaction> f;
    for (auto& t : txs) f.push_back(FilledTransaction{&t, {}});
    auto lev = compute_merkle_root({}, f);
    // reference CBMT root for 1001 leaves
    struct N {
        Hash32 c;
        uint64_t v, s;
    };
    std::vector<N> leaves;
    for (auto& t : txs) {
        Bytes tb = t.canonical_bytes();
        Writer w;
        w.u64(0);
        w.u64(tb.size());
        w.raw(tb);
        leaves.push_back({bt::blake3(w.buf), 0, tb.size()});
    }
    auto merge = [](const N& l, const N& r) {
        Writer w;
        w.raw(l.c);
        w.u64(l.v + r.v);
        w.u64(l.s + r.s);
        w.raw(r.c);
        return N{bt::blake3(w.buf), l.v + r.v, l.s + r.s};
    };
    std::deque<N> q;
    size_t i = leaves.size();
    while (i >= 2) {
        q.push_back(merge(leaves[i - 2], leaves[i - 1]));
        i -= 2;
    }
    if (i == 1) q.push_front(leaves[0]);
    while (q.size() > 1) {
        N r = q.front();
        q.pop_front();
        N l = q.front();
        q.pop_front();
        q.push_back(merge(l, r));
    }
    auto cbr = coinbase_merkle_root({});
    Writer w;
    w.raw(*cbr);
    w.raw(q.front().c);
    Hash32 cbmt = bt::blake3(w.buf);
    REQUIRE(lev.has_value());
    CHECK(*lev != cbmt);
}

TEST(quirk_coinbase_content_checked_only_at_connect)
{
    // §5 #4: prevalidate accepts a coinbase BitName/BitNameReservation output (its value 0
    // is within the fees); connect rejects it (BadCoinbaseOutputContent). Same verdict for a
    // received block; a template must never contain one.
    Chain c;
    c.add(Body{});
    Body b;
    Output o;
    o.address = addr_of(key(4));
    o.content.kind = Content::BitName;
    b.coinbase.outputs.push_back(o);
    Header h = c.make_header(b);
    bt::kv::Txn t(c.store);
    PrevalidatedBlock pre;
    bool prevalidated = true;
    try {
        pre = c.st.prevalidate(t, h, b);
    } catch (const StateError&) {
        prevalidated = false;
    }
    CHECK(prevalidated);
    bool rejected = false;
    try {
        c.st.connect_prevalidated(t, h, b, pre);
    } catch (const StateError& e) {
        rejected = std::string(e.what()) == "BadCoinbaseOutputContent";
    }
    CHECK(rejected);
    // withdrawal outputs in the coinbase are allowed
    Chain c2;
    c2.add(Body{});
    Body bw;
    Output w;
    w.content.kind = Content::Withdrawal;
    w.content.value = 0;
    w.content.main_address = *bt::btc::Address::parse("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    bw.coinbase.outputs.push_back(w);
    c2.add(bw);
}

TEST(quirk_batch_icann_never_validates)
{
    // §5 #6: BATCH_ICANN_VERIFYING_KEY is None (all-zero placeholder), so every BatchIcann
    // transaction fails InvalidBatchIcannRegistrationSignature, even well-formed ones.
    Chain c;
    auto k = key(5);
    c.add(Body{}, deposit(addr_of(k), 1000, 1));
    Transaction t;
    t.inputs.push_back(OutPoint{OutPoint::Deposit, [] {
                                    Hash32 h;
                                    h[0] = 1;
                                    h[1] = 0xd0;
                                    return h;
                                }(),
                                0});
    Output o;
    o.address = addr_of(k);
    o.content.value = 1000;
    t.outputs.push_back(o);
    TxData d;
    d.kind = TxData::BatchIcann;
    d.icann.plain_names = {"example.com"};
    d.icann.signature = sign_with_dst(k, 255, {});
    t.data = d;
    auto at = sign(t, {k});
    bool rejected = false;
    try {
        c.add(Body::from_authorized({at}, {}));
    } catch (const StateError& e) {
        rejected = std::string(e.what()) == "TooFewBitNameOutputs" || std::string(e.what()) == "InvalidBatchIcannRegistrationSignature";
    }
    CHECK(rejected);
    bt::kv::Txn tx(c.store);
    bool mempool_rejected = false;
    try {
        c.st.validate_transaction(tx, at);
    } catch (const StateError&) {
        mempool_rejected = true;
    }
    CHECK(mempool_rejected);
}

TEST(quirk_deposit_address_forms)
{
    // §5 #7: s2_<b58>_<any non-empty hex prefix of sha256, any case> or bare base58;
    // anything else credits Address::ALL_ZEROS.
    Address a;
    for (int i = 0; i < 20; i++) a.b[i] = uint8_t(i + 7);
    auto dep = [](const std::string& s) {
        bt::mainchain::Deposit d;
        d.address.assign(s.begin(), s.end());
        d.value_sats = 5;
        return State::deposit_output(d).address;
    };
    std::string full = a.format_for_deposit();
    std::string prefix = full.substr(0, full.rfind('_') + 1);
    auto digest = bt::hex_encode(bt::sha256(ByteSpan((const uint8_t*)prefix.data(), prefix.size())));
    CHECK(dep(full) == a);
    CHECK(dep(prefix + digest.substr(0, 1)) == a);                    // 1 hex char suffices
    CHECK(dep(prefix + digest) == a);                                 // all 64
    std::string upper = digest.substr(0, 6);
    for (auto& ch : upper) ch = char(std::toupper((unsigned char)ch));
    CHECK(dep(prefix + upper) == a);                                  // case-insensitive
    CHECK(dep(a.to_base58()) == a);                                   // bare base58
    CHECK(dep(prefix) == Address::ALL_ZEROS);                         // empty checksum
    CHECK(dep(prefix + (digest[0] == 'f' ? "e" : "f")) == Address::ALL_ZEROS); // wrong checksum
    CHECK(dep("s9_" + a.to_base58() + "_" + digest.substr(0, 6)) == Address::ALL_ZEROS); // other slot
    CHECK(dep(std::string("\xff\xfe", 2)) == Address::ALL_ZEROS);     // not UTF-8
    CHECK(dep("1111111111111111111111") == Address::ALL_ZEROS);       // 22 zero bytes
}

TEST(quirk_registration_requires_matching_reservation)
{
    // fork f0ba71e / mod.rs:469-488: a registration must burn a reservation committing to
    // keyed_hash(nonce, name); counts: reservations in = out + 1, names out = in + 1.
    Chain c;
    auto k = key(6);
    Hash32 name = name_hash("x"), nonce, wrong;
    nonce.v.fill(3);
    wrong.v.fill(4);
    Transaction r = reservation_tx(addr_of(k), commit_for(wrong, name));
    Body b0;
    b0.transactions = {r};
    c.add(b0);
    Transaction t;
    t.inputs.push_back(OutPoint{OutPoint::Regular, r.txid(), 0});
    Output o;
    o.address = addr_of(k);
    o.content.kind = Content::BitName;
    t.outputs.push_back(o);
    TxData d;
    d.kind = TxData::Registration;
    d.name_hash = name;
    d.revealed_nonce = nonce;
    t.data = d;
    bool rejected = false;
    try {
        c.add(Body::from_authorized({sign(t, {k})}, {}));
    } catch (const StateError& e) {
        rejected = std::string(e.what()) == "NoReservationForRegistration";
    }
    CHECK(rejected);
}
