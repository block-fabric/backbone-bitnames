// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <bitnames/wallet.h>

#include <bt/crypto.h>
#include <bt/ecies.h>
#include <bt/hd.h>
#include <bt/log.h>

#include <algorithm>
#include <cstring>

#include <sodium.h>

namespace bitnames {

using bt::kv::Txn;

enum : uint8_t {
    W_SEED = 1, W_INDEX_TO_ADDR, W_ADDR_TO_INDEX, W_INDEX_TO_EPK, W_EPK_TO_INDEX, W_INDEX_TO_VK, W_VK_TO_INDEX,
    W_RESERVATIONS, W_KNOWN_NAMES
};

static constexpr uint32_t HARD = 0x80000000u;

Wallet::Wallet(const std::string& path, Node& node) : store_(bt::kv::open_sqlite(path)), node_(node) {}

// ------------------------------------------------------------------ keys (lib/wallet/mod.rs:190-380)
bt::ed25519_bip32::XPrv Wallet::master_xprv(const bt::ByteArray<64>& seed)
{
    Hash32 secret = bt::sha256(seed.span());
    for (;;) {
        uint8_t one = 0x01;
        Hash32 cc = bt::sha256_parts({ByteSpan(&one, 1), secret.span()});
        if (auto x = bt::ed25519_bip32::XPrv::from_nonextended_noforce(secret, cc)) return *x;
        secret = bt::sha256(secret.span());
    }
}

static bt::frost::SigningKey frost_key(const bt::ed25519_bip32::XPrv& x)
{
    bt::ByteArray<64> wide{};
    std::memcpy(wide.data(), x.b.data(), 32);
    bt::frost::SigningKey k{bt::frost::reduce_wide(wide)}; // Scalar::from_bytes_mod_order(kL)
    if (k.s.is_zero()) throw WalletError("expected secret scalar to be non-zero");
    return k;
}

bt::frost::SigningKey Wallet::tx_signing_key(const bt::ByteArray<64>& seed, uint32_t index)
{
    return frost_key(master_xprv(seed).derive(HARD | 0).derive(index));
}

bt::frost::SigningKey Wallet::message_signing_key(const bt::ByteArray<64>& seed, uint32_t index)
{
    return frost_key(master_xprv(seed).derive(HARD | 2).derive(index));
}

bt::ByteArray<32> Wallet::encryption_secret(const bt::ByteArray<64>& seed, uint32_t index)
{
    auto x = master_xprv(seed).derive(HARD | 1).derive(index);
    return bt::ByteArray<32>::from_span(x.kl()); // StaticSecret::from(kL)
}

static std::string base58ck_with_prefix(std::initializer_list<uint8_t> prefix, ByteSpan payload)
{
    Bytes b(prefix);
    append(b, payload);
    return bt::base58check_encode(b);
}

std::string Wallet::master_xvk()
{
    auto x = master_xprv(need_seed()).derive(HARD | 0);
    return base58ck_with_prefix({0x9f, 0x48, 0x71, 0x91, 0x4b}, x.xpub().span());
}

std::string Wallet::master_xesk()
{
    auto x = master_xprv(need_seed()).derive(HARD | 1);
    return base58ck_with_prefix({0x79, 0x7b, 0x44, 0x3e, 0xb7, 0x3b}, x.b.span());
}

// ------------------------------------------------------------------ seed and indexes
std::optional<bt::ByteArray<64>> Wallet::seed()
{
    Txn t(*store_);
    auto v = t.get(W_SEED, Bytes{0});
    if (!v || v->size() != 64) return std::nullopt;
    return bt::ByteArray<64>::from_span(*v);
}

std::optional<Hash32> Wallet::seed_digest(std::string_view label)
{
    std::lock_guard<std::mutex> l(mu_);
    auto s = seed();
    if (!s) return std::nullopt;
    const uint8_t zero = 0;
    Hash32 h = bt::sha256_parts({ByteSpan(reinterpret_cast<const uint8_t*>(label.data()), label.size()), ByteSpan(&zero, 1), s->span()});
    sodium_memzero(s->data(), s->size());
    return h;
}

bt::ByteArray<64> Wallet::need_seed()
{
    auto s = seed();
    if (!s) throw WalletError("no seed");
    return *s;
}

bool Wallet::has_seed()
{
    std::lock_guard<std::mutex> l(mu_);
    return seed().has_value();
}

void Wallet::set_seed(const bt::ByteArray<64>& s)
{
    std::lock_guard<std::mutex> l(mu_);
    auto cur = seed();
    if (cur) {
        if (*cur == s) return;
        throw WalletError("seed already exists");
    }
    Txn t(*store_);
    t.put(W_SEED, Bytes{0}, s.span());
    for (uint8_t tb : {W_INDEX_TO_ADDR, W_ADDR_TO_INDEX, W_RESERVATIONS}) t.clear(tb);
    t.commit();
}

void Wallet::set_seed_from_mnemonic(const std::string& mnemonic)
{
    auto p = bt::hd::parse_mnemonic(mnemonic);
    if (!p) throw WalletError("failed to parse mnemonic seed phrase: " + bt::hd::mnemonic_error(mnemonic));
    set_seed(bt::hd::mnemonic_to_seed(*p));
}

static Bytes be32(uint32_t v)
{
    Writer w;
    w.u32be(v);
    return w.buf;
}
static uint32_t from_be32(ByteSpan b) { return uint32_t(b[0]) << 24 | uint32_t(b[1]) << 16 | uint32_t(b[2]) << 8 | b[3]; }

std::optional<uint32_t> Wallet::index_of(uint8_t table, ByteSpan key)
{
    Txn t(*store_);
    auto v = t.get(table, key);
    if (!v) return std::nullopt;
    return from_be32(*v);
}

static uint32_t next_index(const Txn& t, uint8_t table)
{
    auto l = t.last(table);
    return l ? from_be32(l->first) + 1 : 0;
}

Address Wallet::get_new_address()
{
    std::lock_guard<std::mutex> l(mu_);
    auto s = need_seed();
    Txn t(*store_);
    uint32_t index = next_index(t, W_INDEX_TO_ADDR);
    Address a = address_from_vk(tx_signing_key(s, index).verifying_key());
    t.put(W_INDEX_TO_ADDR, be32(index), a.b.span());
    t.put(W_ADDR_TO_INDEX, a.b.span(), be32(index));
    t.commit();
    return a;
}

bool Wallet::is_mine(const Address& a) { return index_of(W_ADDR_TO_INDEX, a.b.span()).has_value(); }

Address Wallet::get_receive_address()
{
    std::optional<Address> last;
    {
        std::lock_guard<std::mutex> l(mu_);
        Txn t(*store_);
        if (auto lv = t.last(W_INDEX_TO_ADDR)) {
            Address a;
            std::memcpy(a.b.data(), lv->second.data(), 20);
            last = a;
        }
    }
    if (last) {
        std::set<Address> s{*last};
        if (node_.utxos_by_addresses(s).empty() && node_.stxos_by_addresses(s).empty()) return *last;
    }
    return get_new_address();
}

std::vector<Address> Wallet::addresses()
{
    std::lock_guard<std::mutex> l(mu_);
    Txn t(*store_);
    std::vector<Address> r;
    t.scan(W_INDEX_TO_ADDR, [&](ByteSpan, ByteSpan v) {
        Address a;
        std::memcpy(a.b.data(), v.data(), 20);
        r.push_back(a);
        return true;
    });
    std::sort(r.begin(), r.end(), [](const Address& a, const Address& b) { return a.to_base58() < b.to_base58(); });
    return r;
}

bt::ByteArray<32> Wallet::get_new_encryption_key()
{
    std::lock_guard<std::mutex> l(mu_);
    auto s = need_seed();
    Txn t(*store_);
    uint32_t index = next_index(t, W_INDEX_TO_EPK);
    auto epk = bt::ecies::x25519_public(encryption_secret(s, index));
    t.put(W_INDEX_TO_EPK, be32(index), epk.span());
    t.put(W_EPK_TO_INDEX, epk.span(), be32(index));
    t.commit();
    return epk;
}

bt::frost::Point Wallet::get_new_verifying_key()
{
    std::lock_guard<std::mutex> l(mu_);
    auto s = need_seed();
    Txn t(*store_);
    uint32_t index = next_index(t, W_INDEX_TO_VK);
    auto vk = message_signing_key(s, index).verifying_key();
    t.put(W_INDEX_TO_VK, be32(index), vk.span());
    t.put(W_VK_TO_INDEX, vk.span(), be32(index));
    t.commit();
    return vk;
}

bt::frost::SigningKey Wallet::key_for_address(const Address& a)
{
    auto idx = index_of(W_ADDR_TO_INDEX, a.b.span());
    if (!idx) throw WalletError("Address does not exist: " + a.to_base58());
    auto k = tx_signing_key(need_seed(), *idx);
    if (address_from_vk(k.verifying_key()) != a) throw WalletError("signing key does not match the address");
    return k;
}

std::optional<std::string> Wallet::plain_name(const Hash32& name)
{
    Txn t(*store_);
    auto v = t.get(W_KNOWN_NAMES, name.span());
    if (!v) return std::nullopt;
    return std::string(v->begin(), v->end());
}

std::optional<std::string> Wallet::reserved_name(const Hash32& commitment)
{
    Txn t(*store_);
    auto v = t.get(W_RESERVATIONS, commitment.span());
    if (!v) return std::nullopt;
    return std::string(v->begin(), v->end());
}

// ------------------------------------------------------------------ coins
std::vector<std::pair<OutPoint, FilledOutput>> Wallet::utxos()
{
    auto a = addresses();
    return node_.utxos_by_addresses(std::set<Address>(a.begin(), a.end()));
}

std::vector<std::pair<OutPoint, SpentOutput>> Wallet::stxos()
{
    auto a = addresses();
    return node_.stxos_by_addresses(std::set<Address>(a.begin(), a.end()));
}

Balance Wallet::balance()
{
    Balance b;
    for (auto& [op, o] : utxos()) {
        uint64_t v = o.get_value();
        if (b.total + v < b.total) throw WalletError("AmountOverflow");
        b.total += v;
        if (!o.content.is_withdrawal()) b.available += v;
    }
    return b;
}

std::set<OutPoint> Wallet::pending_inputs()
{
    std::set<OutPoint> r;
    for (auto& tx : node_.mempool())
        for (auto& op : tx.transaction.inputs) r.insert(op);
    return r;
}

// wallet/mod.rs:805-839: ascending value, skip pending/withdrawal/name/reservation/zero,
// stop once the total reaches the target.
std::pair<uint64_t, std::vector<std::pair<OutPoint, FilledOutput>>> Wallet::select_coins(uint64_t value)
{
    auto u = utxos();
    std::stable_sort(u.begin(), u.end(), [](auto& a, auto& b) { return a.second.get_value() < b.second.get_value(); });
    auto pending = pending_inputs();
    uint64_t total = 0;
    std::vector<std::pair<OutPoint, FilledOutput>> sel;
    for (auto& [op, o] : u) {
        if (pending.count(op) || o.content.is_withdrawal() || o.content.is_bitname() || o.content.is_reservation() || o.get_value() == 0) continue;
        if (total >= value) break;
        if (total + o.get_value() < total) throw WalletError("AmountOverflow");
        total += o.get_value();
        sel.emplace_back(op, o);
    }
    if (total < value) throw WalletError("not enough funds");
    return {total, sel};
}

static Output value_output(const Address& a, uint64_t v)
{
    Output o;
    o.address = a;
    o.content.kind = Content::Bitcoin;
    o.content.value = v;
    return o;
}

Transaction Wallet::create_transfer(const Address& dest, uint64_t value, uint64_t fee, const Bytes& memo)
{
    if (value + fee < value) throw WalletError("AmountOverflow");
    auto [total, coins] = select_coins(value + fee);
    uint64_t change = total - value - fee;
    Transaction tx;
    for (auto& [op, _] : coins) tx.inputs.push_back(op);
    Output o = value_output(dest, value);
    o.memo = memo;
    tx.outputs.push_back(o);
    if (change != 0) tx.outputs.push_back(value_output(get_new_address(), change));
    return tx;
}

Transaction Wallet::create_transfer_many(const std::map<Address, uint64_t>& dests, uint64_t fee)
{
    if (dests.empty()) throw WalletError("no transfer destination");
    uint64_t value = 0;
    for (auto& [a, v] : dests) {
        if (value + v < value) throw WalletError("AmountOverflow");
        value += v;
    }
    if (value + fee < value) throw WalletError("AmountOverflow");
    auto [total, coins] = select_coins(value + fee);
    uint64_t change = total - value - fee;
    Transaction tx;
    for (auto& [op, _] : coins) tx.inputs.push_back(op);
    for (auto& [a, v] : dests) tx.outputs.push_back(value_output(a, v));
    if (change != 0) tx.outputs.push_back(value_output(get_new_address(), change));
    return tx;
}

Transaction Wallet::create_withdrawal(const bt::btc::Address& main_address, uint64_t value, uint64_t main_fee, uint64_t fee)
{
    if (value + fee < value || value + fee + main_fee < value + fee) throw WalletError("AmountOverflow");
    auto [total, coins] = select_coins(value + fee + main_fee);
    uint64_t change = total - value - fee - main_fee;
    Transaction tx;
    for (auto& [op, _] : coins) tx.inputs.push_back(op);
    Output w;
    w.address = get_new_address();
    w.content.kind = Content::Withdrawal;
    w.content.value = value;
    w.content.main_fee = main_fee;
    w.content.main_address = main_address;
    tx.outputs.push_back(w);
    tx.outputs.push_back(value_output(get_new_address(), change));
    return tx;
}

static Hash32 keyed(const Hash32& key, ByteSpan data)
{
    bt::Blake3 h(key);
    h.update(data);
    return h.finalize();
}

// wallet/mod.rs:652-714
Transaction Wallet::reserve_bitname(const std::string& plain)
{
    Transaction tx;
    // Policy (consensus-neutral): spend one coin back to ourselves so the reservation has an
    // input; a zero-input reservation can be replayed by anyone (§5 #2).
    try {
        auto [total, coins] = select_coins(1);
        tx.inputs.push_back(coins.front().first);
        tx.outputs.push_back(value_output(get_new_address(), total));
    } catch (const WalletError&) {
        LOG_WARN("reserve_bitname: no coin to spend; the reservation has no inputs and can be replayed");
    }
    Address raddr = tx.outputs.empty() || !is_mine(tx.outputs.back().address) ? get_new_address() : tx.outputs.back().address;
    auto sk = key_for_address(raddr);
    Hash32 name = name_hash(plain);
    Hash32 hmac_key = bt::blake3(sk.s.span());
    Hash32 nonce = keyed(hmac_key, name.span());
    Hash32 commitment = keyed(nonce, name.span());
    {
        std::lock_guard<std::mutex> l(mu_);
        Txn t(*store_);
        t.put(W_RESERVATIONS, commitment.span(), ByteSpan((const uint8_t*)plain.data(), plain.size()));
        t.put(W_KNOWN_NAMES, name.span(), ByteSpan((const uint8_t*)plain.data(), plain.size()));
        t.commit();
    }
    Output r;
    r.address = raddr;
    r.content.kind = Content::BitNameReservation;
    tx.outputs.push_back(r);
    TxData d;
    d.kind = TxData::Reservation;
    d.commitment = commitment;
    tx.data = d;
    return tx;
}

// wallet/mod.rs:716-793
Transaction Wallet::register_bitname(const std::string& plain, const MutableBitNameData& data)
{
    Hash32 name = name_hash(plain);
    std::optional<std::pair<OutPoint, Hash32>> found;
    for (auto& [op, o] : utxos()) {
        if (!o.content.is_reservation()) continue;
        auto sk = key_for_address(o.address);
        Hash32 nonce = keyed(bt::blake3(sk.s.span()), name.span());
        if (keyed(nonce, name.span()) == o.content.reservation_commitment) {
            found = std::make_pair(op, nonce);
            break;
        }
    }
    {
        std::lock_guard<std::mutex> l(mu_);
        Txn t(*store_);
        t.put(W_KNOWN_NAMES, name.span(), ByteSpan((const uint8_t*)plain.data(), plain.size()));
        t.commit();
    }
    if (!found) throw WalletError("could not find bitname reservation for `" + plain + "`");
    Transaction tx;
    tx.inputs.push_back(found->first);
    Output o;
    o.address = get_new_address();
    o.content.kind = Content::BitName;
    tx.outputs.push_back(o);
    TxData d;
    d.kind = TxData::Registration;
    d.name_hash = name;
    d.revealed_nonce = found->second;
    d.data = data;
    tx.data = d;
    return tx;
}

AuthorizedTransaction Wallet::authorize(const Transaction& tx)
{
    AuthorizedTransaction at;
    at.transaction = tx;
    Bytes msg = tx_signing_message(tx);
    auto mine = utxos();
    for (auto& op : tx.inputs) {
        auto it = std::find_if(mine.begin(), mine.end(), [&](auto& p) { return p.first == op; });
        if (it == mine.end()) throw WalletError("NoUtxo " + op.to_string());
        auto sk = key_for_address(it->second.address);
        at.authorizations.push_back(Authorization{sk.verifying_key(), sk.sign(msg)});
    }
    return at;
}

bt::frost::Signature Wallet::sign_arbitrary_msg(const bt::frost::Point& vk, const std::string& msg)
{
    auto idx = index_of(W_VK_TO_INDEX, vk.span());
    if (!idx) throw WalletError("Message signature verification key " + vk_to_string(vk) + " does not exist");
    auto sk = message_signing_key(need_seed(), *idx);
    return sign_with_dst(sk, 255, ByteSpan((const uint8_t*)msg.data(), msg.size()));
}

Authorization Wallet::sign_arbitrary_msg_as_addr(const Address& a, const std::string& msg)
{
    auto sk = key_for_address(a);
    return Authorization{sk.verifying_key(), sign_with_dst(sk, 255, ByteSpan((const uint8_t*)msg.data(), msg.size()))};
}

Bytes Wallet::decrypt_msg(const bt::ByteArray<32>& epk, ByteSpan ct)
{
    auto idx = index_of(W_EPK_TO_INDEX, epk.span());
    if (!idx) throw WalletError("Encryption pubkey " + epk_to_string(epk) + " does not exist");
    auto pt = bt::ecies::decrypt(encryption_secret(need_seed(), *idx), ct);
    if (!pt) throw WalletError("ECIES decryption failed");
    return *pt;
}

} // namespace bitnames
