// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <bitnames/types.h>

#include <bt/bech32.h>
#include <bt/crypto.h>
#include <bt/parse.h>

#include <cstring>
#include <deque>

namespace bitnames {

using bt::DecodeError;

const Address Address::ALL_ZEROS{};

// ---------------------------------------------------------------- addresses and keys
std::string Address::to_base58() const { return bt::base58_encode(b.span()); }

std::optional<Address> Address::from_base58(std::string_view s)
{
    auto d = bt::base58_decode(s);
    if (!d || d->size() != 20) return std::nullopt;
    Address a;
    std::memcpy(a.b.data(), d->data(), 20);
    return a;
}

std::string Address::format_for_deposit() const
{
    std::string prefix = "s" + std::to_string(THIS_SIDECHAIN) + "_" + to_base58() + "_";
    auto d = bt::sha256(ByteSpan((const uint8_t*)prefix.data(), prefix.size()));
    return prefix + bt::hex_encode(ByteSpan(d.data(), 3));
}

std::optional<Address> Address::from_deposit_address(std::string_view s)
{
    const std::string prefix = "s" + std::to_string(THIS_SIDECHAIN) + "_";
    if (s.substr(0, prefix.size()) != prefix) return std::nullopt; // MissingDepositPrefix
    std::string_view rest = s.substr(prefix.size());
    auto us = rest.rfind('_');
    if (us == std::string_view::npos) return std::nullopt;
    std::string_view addr = rest.substr(0, us), checksum = rest.substr(us + 1);
    if (checksum.empty()) return std::nullopt; // MissingDepositChecksum
    std::string pre = prefix + std::string(addr) + "_";
    std::string digest = bt::hex_encode(bt::sha256(ByteSpan((const uint8_t*)pre.data(), pre.size())).span());
    // const_hex::encode(digest).starts_with(&checksum.to_lowercase()): only ASCII can lower
    // to a hex digit, so a non-ASCII checksum never matches.
    if (checksum.size() > digest.size()) return std::nullopt;
    for (size_t i = 0; i < checksum.size(); i++) {
        unsigned char c = (unsigned char)checksum[i];
        if (c >= 0x80) return std::nullopt;
        if (char(std::tolower(c)) != digest[i]) return std::nullopt; // WrongDepositChecksum
    }
    return from_base58(addr);
}

Address address_from_vk(const bt::frost::Point& vk)
{
    bt::Blake3 h;
    h.update(vk.span());
    Address a;
    h.finalize_xof(a.b.data(), 20);
    return a;
}

std::string vk_to_string(const bt::frost::Point& vk) { return *bt::bech32::encode("bn-svk", vk.span()); }

std::optional<bt::frost::Point> vk_from_string(std::string_view s)
{
    auto d = bt::bech32::decode_bech32m_canonical(s, "bn-svk");
    if (!d || d->size() != 32) return std::nullopt;
    auto p = bt::frost::Point::from_span(*d);
    if (!bt::frost::valid_element(p)) return std::nullopt; // VerifyingKey::deserialize
    return p;
}

std::string epk_to_string(const bt::ByteArray<32>& k) { return *bt::bech32::encode("bn-enc", k.span()); }

std::optional<bt::ByteArray<32>> epk_from_string(std::string_view s)
{
    auto d = bt::bech32::decode_bech32m_canonical(s, "bn-enc");
    if (!d || d->size() != 32) return std::nullopt;
    return bt::ByteArray<32>::from_span(*d);
}

// ---------------------------------------------------------------- socket addresses
static std::string ipv4_str(const uint8_t* ip)
{
    return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." + std::to_string(ip[2]) + "." + std::to_string(ip[3]);
}

std::string SocketV4::to_string() const { return ipv4_str(ip.data()) + ":" + std::to_string(port); }

// Rust Ipv4Addr::from_str: four decimal octets, no leading zeros, <= 255.
static bool parse_ipv4(std::string_view s, uint8_t* out)
{
    int part = 0;
    size_t i = 0;
    while (part < 4) {
        size_t j = i;
        while (j < s.size() && s[j] >= '0' && s[j] <= '9') j++;
        if (j == i || j - i > 3) return false;
        if (j - i > 1 && s[i] == '0') return false;
        int v = 0;
        for (size_t k = i; k < j; k++) v = v * 10 + (s[k] - '0');
        if (v > 255) return false;
        out[part++] = uint8_t(v);
        if (part < 4) {
            if (j >= s.size() || s[j] != '.') return false;
            i = j + 1;
        } else {
            i = j;
        }
    }
    return i == s.size();
}

std::optional<SocketV4> SocketV4::parse(std::string_view s)
{
    auto c = s.rfind(':');
    if (c == std::string_view::npos) return std::nullopt;
    SocketV4 r;
    if (!parse_ipv4(s.substr(0, c), r.ip.data())) return std::nullopt;
    auto p = bt::parse_u64(s.substr(c + 1));
    if (!p || *p > 65535) return std::nullopt;
    r.port = uint16_t(*p);
    return r;
}

// Rust's Display for Ipv6Addr: IPv4-mapped as ::ffff:a.b.c.d, otherwise the longest run
// (first if tied) of two or more zero segments collapses to "::", lowercase hex.
static std::string ipv6_str(const std::array<uint8_t, 16>& b)
{
    uint16_t seg[8];
    for (int i = 0; i < 8; i++) seg[i] = uint16_t(b[2 * i] << 8 | b[2 * i + 1]);
    bool mapped = true;
    for (int i = 0; i < 5; i++)
        if (seg[i]) mapped = false;
    if (mapped && seg[5] == 0xffff) return "::ffff:" + ipv4_str(b.data() + 12);
    int best = -1, best_len = 0;
    for (int i = 0; i < 8;) {
        if (seg[i] != 0) {
            i++;
            continue;
        }
        int j = i;
        while (j < 8 && seg[j] == 0) j++;
        if (j - i > best_len) {
            best = i;
            best_len = j - i;
        }
        i = j;
    }
    auto hexs = [](uint16_t v) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "%x", v);
        return std::string(buf);
    };
    std::string r;
    if (best_len > 1) {
        for (int i = 0; i < best; i++) r += (i ? ":" : "") + hexs(seg[i]);
        r += "::";
        for (int i = best + best_len; i < 8; i++) r += (i > best + best_len ? ":" : "") + hexs(seg[i]);
    } else {
        for (int i = 0; i < 8; i++) r += (i ? ":" : "") + hexs(seg[i]);
    }
    return r;
}

std::string SocketV6::to_string() const { return "[" + ipv6_str(ip) + "]:" + std::to_string(port); }

static bool parse_ipv6(std::string_view s, std::array<uint8_t, 16>& out)
{
    std::vector<uint16_t> head, tail;
    bool dbl = false;
    auto dc = s.find("::");
    auto parse_groups = [](std::string_view p, std::vector<uint16_t>& g, std::array<uint8_t, 4>* v4, bool& has_v4) -> bool {
        if (p.empty()) return true;
        size_t i = 0;
        while (i <= p.size()) {
            size_t j = p.find(':', i);
            std::string_view part = p.substr(i, j == std::string_view::npos ? std::string_view::npos : j - i);
            if (j == std::string_view::npos && part.find('.') != std::string_view::npos) {
                if (!parse_ipv4(part, v4->data())) return false;
                has_v4 = true;
                return true;
            }
            if (part.empty() || part.size() > 4) return false;
            uint32_t v = 0;
            for (char c : part) {
                int d = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
                if (d < 0) return false;
                v = v * 16 + uint32_t(d);
            }
            g.push_back(uint16_t(v));
            if (j == std::string_view::npos) break;
            i = j + 1;
        }
        return true;
    };
    std::array<uint8_t, 4> v4{};
    bool has_v4 = false, dummy = false;
    if (dc != std::string_view::npos) {
        dbl = true;
        if (!parse_groups(s.substr(0, dc), head, &v4, dummy) || dummy) return false;
        if (!parse_groups(s.substr(dc + 2), tail, &v4, has_v4)) return false;
    } else {
        if (!parse_groups(s, head, &v4, has_v4)) return false;
    }
    size_t n = head.size() + tail.size() + (has_v4 ? 2 : 0);
    if (dbl ? n > 7 : n != 8) return false;
    std::vector<uint16_t> all = head;
    if (dbl) all.insert(all.end(), 8 - n, 0);
    all.insert(all.end(), tail.begin(), tail.end());
    if (has_v4) {
        all.push_back(uint16_t(v4[0] << 8 | v4[1]));
        all.push_back(uint16_t(v4[2] << 8 | v4[3]));
    }
    for (int i = 0; i < 8; i++) {
        out[2 * i] = uint8_t(all[i] >> 8);
        out[2 * i + 1] = uint8_t(all[i]);
    }
    return true;
}

std::optional<SocketV6> SocketV6::parse(std::string_view s)
{
    if (s.empty() || s[0] != '[') return std::nullopt;
    auto e = s.find(']');
    if (e == std::string_view::npos || e + 1 >= s.size() || s[e + 1] != ':') return std::nullopt;
    SocketV6 r;
    std::string_view ip = s.substr(1, e - 1);
    if (ip.find('%') != std::string_view::npos) return std::nullopt; // scope ids are not encoded
    if (!parse_ipv6(ip, r.ip)) return std::nullopt;
    auto p = bt::parse_u64(s.substr(e + 2));
    if (!p || *p > 65535) return std::nullopt;
    r.port = uint16_t(*p);
    return r;
}

// ---------------------------------------------------------------- contents
uint64_t Content::get_value() const
{
    switch (kind) {
    case Bitcoin: return value;
    case BitName:
    case BitNameReservation: return 0;
    case Withdrawal: {
        uint64_t s = value + main_fee;
        return s < value ? UINT64_MAX : s;
    }
    }
    return 0;
}

bool Content::operator==(const Content& o) const
{
    if (kind != o.kind) return false;
    switch (kind) {
    case Bitcoin: return value == o.value;
    case BitName:
    case BitNameReservation: return true;
    case Withdrawal: return value == o.value && main_fee == o.main_fee && main_address == o.main_address;
    }
    return false;
}

uint64_t FilledContent::get_value() const { return to_content().get_value(); }

Content FilledContent::to_content() const
{
    Content c;
    switch (kind) {
    case Bitcoin: c.kind = Content::Bitcoin; c.value = value; break;
    case BitcoinWithdrawal:
        c.kind = Content::Withdrawal;
        c.value = value;
        c.main_fee = main_fee;
        c.main_address = main_address;
        break;
    case BitName: c.kind = Content::BitName; break;
    case BitNameReservation: c.kind = Content::BitNameReservation; break;
    }
    return c;
}

bool FilledContent::operator==(const FilledContent& o) const
{
    if (kind != o.kind) return false;
    switch (kind) {
    case Bitcoin: return value == o.value;
    case BitcoinWithdrawal: return value == o.value && main_fee == o.main_fee && main_address == o.main_address;
    case BitName: return bitname == o.bitname;
    case BitNameReservation: return reservation_txid == o.reservation_txid && reservation_commitment == o.reservation_commitment;
    }
    return false;
}

// ---------------------------------------------------------------- outpoints
std::array<uint8_t, 37> OutPoint::key() const
{
    std::array<uint8_t, 37> k{};
    k[0] = kind;
    std::memcpy(k.data() + 1, txid.data(), 32);
    for (int i = 0; i < 4; i++) k[33 + i] = uint8_t(vout >> (8 * i));
    return k;
}

OutPoint OutPoint::from_key(ByteSpan k)
{
    if (k.size() != 37 || k[0] > 2) throw DecodeError("bad OutPointKey");
    OutPoint o;
    o.kind = Kind(k[0]);
    std::memcpy(o.txid.data(), k.data() + 1, 32);
    o.vout = uint32_t(k[33]) | uint32_t(k[34]) << 8 | uint32_t(k[35]) << 16 | uint32_t(k[36]) << 24;
    return o;
}

std::string OutPoint::to_string() const
{
    switch (kind) {
    case Regular: return "regular " + bt::hex_encode(txid) + " " + std::to_string(vout);
    case Coinbase: return "coinbase " + bt::hex_encode(txid) + " " + std::to_string(vout);
    case Deposit: return "deposit " + bt::hex_encode_rev(txid.span()) + " " + std::to_string(vout);
    }
    return {};
}

// ---------------------------------------------------------------- transactions
std::optional<Hash32> Transaction::implied_reservation_commitment() const
{
    if (!is_registration()) return std::nullopt;
    bt::Blake3 h(data->revealed_nonce);
    h.update(data->name_hash.span());
    return h.finalize();
}

Hash32 Transaction::txid() const { return bt::blake3(canonical_bytes()); }
Bytes Transaction::canonical_bytes() const { return borsh_bytes(*this); }

Hash32 Header::hash() const { return bitnames::hash(*this); }
Hash32 Header::coinbase_txid() const { return compute_coinbase_txid(merkle_root, prev_main_hash, prev_side_hash); }

Hash32 compute_coinbase_txid(const Hash32& merkle_root, const Hash32& prev_main_hash, const std::optional<Hash32>& prev_side)
{
    Writer w;
    w.raw(merkle_root);
    w.raw(prev_main_hash);
    if (prev_side) {
        w.u8(1);
        w.raw(*prev_side);
    } else {
        w.u8(0);
    }
    return bt::blake3(w.buf);
}

size_t Body::inputs_len() const
{
    size_t n = 0;
    for (auto& t : transactions) n += t.inputs.size();
    return n;
}

std::vector<AuthorizedTransaction> Body::authorized_transactions() const
{
    std::vector<AuthorizedTransaction> r;
    size_t k = 0;
    for (auto& t : transactions) {
        AuthorizedTransaction at;
        at.transaction = t;
        for (size_t i = 0; i < t.inputs.size() && k < authorizations.size(); i++) at.authorizations.push_back(authorizations[k++]);
        r.push_back(std::move(at));
    }
    return r;
}

Body Body::from_authorized(std::vector<AuthorizedTransaction> txs, Coinbase cb)
{
    Body b;
    b.coinbase = std::move(cb);
    for (auto& t : txs) {
        for (auto& a : t.authorizations) b.authorizations.push_back(a);
        b.transactions.push_back(std::move(t.transaction));
    }
    return b;
}

std::optional<uint64_t> FilledTransaction::fee() const
{
    uint64_t in = 0, out = 0;
    for (auto& o : spent_utxos) {
        uint64_t v = o.get_value();
        if (in + v < in) return std::nullopt;
        in += v;
    }
    for (auto& o : tx->outputs) {
        uint64_t v = o.get_value();
        if (out + v < out) return std::nullopt;
        out += v;
    }
    if (in < out) return std::nullopt;
    return in - out;
}

std::optional<std::vector<FilledOutput>> FilledTransaction::filled_outputs() const
{
    // spent BitNames in input order, then the newly registered name
    std::deque<FilledContent> names;
    for (auto& u : spent_utxos)
        if (u.content.is_bitname()) names.push_back(u.content);
    if (tx->is_registration()) {
        FilledContent c;
        c.kind = FilledContent::BitName;
        c.bitname = tx->data->name_hash;
        names.push_back(c);
    }
    // spent reservations, minus the first one a registration burns, then the new one
    std::deque<FilledContent> res;
    auto burn = tx->implied_reservation_commitment();
    for (auto& u : spent_utxos) {
        if (!u.content.is_reservation()) continue;
        if (burn && u.content.reservation_commitment == *burn) {
            burn.reset();
            continue;
        }
        res.push_back(u.content);
    }
    if (tx->is_reservation()) {
        FilledContent c;
        c.kind = FilledContent::BitNameReservation;
        c.reservation_txid = tx->txid();
        c.reservation_commitment = tx->data->commitment;
        res.push_back(c);
    }
    std::vector<FilledOutput> out;
    for (auto& o : tx->outputs) {
        FilledOutput f;
        f.address = o.address;
        f.memo = o.memo;
        switch (o.content.kind) {
        case Content::BitName:
            if (names.empty()) return std::nullopt;
            f.content = names.front();
            names.pop_front();
            break;
        case Content::BitNameReservation:
            if (res.empty()) return std::nullopt;
            f.content = res.front();
            res.pop_front();
            break;
        case Content::Bitcoin:
            f.content.kind = FilledContent::Bitcoin;
            f.content.value = o.content.value;
            break;
        case Content::Withdrawal:
            f.content.kind = FilledContent::BitcoinWithdrawal;
            f.content.value = o.content.value;
            f.content.main_fee = o.content.main_fee;
            f.content.main_address = o.content.main_address;
            break;
        }
        out.push_back(std::move(f));
    }
    return out;
}

std::vector<FilledOutput> FilledTransaction::spent_utxos_requiring_auth() const
{
    if (!tx->is_batch_icann()) return spent_utxos;
    std::vector<Hash32> names;
    for (auto& n : tx->data->icann.plain_names) names.push_back(name_hash(n));
    size_t k = 0;
    std::vector<FilledOutput> r;
    for (auto& u : spent_utxos) {
        if (!u.content.is_bitname() || k >= names.size()) {
            r.push_back(u);
            continue;
        }
        if (u.content.bitname == names[k]) {
            k++;
            continue;
        }
        r.push_back(u);
    }
    return r;
}

Hash32 name_hash(std::string_view plain) { return bt::blake3(ByteSpan((const uint8_t*)plain.data(), plain.size())); }

// ---------------------------------------------------------------- borsh
void borsh(Writer& w, const Address& a) { w.raw(a.b); }

void borsh(Writer& w, const Content& c)
{
    w.u8(c.kind);
    switch (c.kind) {
    case Content::Bitcoin: w.u64(c.value); break;
    case Content::BitName:
    case Content::BitNameReservation: break;
    case Content::Withdrawal:
        w.u64(c.value);
        w.u64(c.main_fee);
        w.borsh_bytes(c.main_address.script_pubkey());
        break;
    }
}

void borsh(Writer& w, const Output& o)
{
    borsh(w, o.address);
    borsh(w, o.content);
    w.borsh_bytes(o.memo);
}

void borsh(Writer& w, const OutPoint& o)
{
    w.u8(o.kind);
    w.raw(o.txid);
    w.u32(o.vout);
}

template <class T, class F>
static void borsh_opt(Writer& w, const std::optional<T>& v, F f)
{
    if (v) {
        w.u8(1);
        f(*v);
    } else {
        w.u8(0);
    }
}

static void raw_v4(Writer& w, const SocketV4& s)
{
    w.raw(ByteSpan(s.ip.data(), 4));
    w.u16(s.port);
}
static void raw_v6(Writer& w, const SocketV6& s)
{
    w.raw(ByteSpan(s.ip.data(), 16));
    w.u16(s.port);
}

void borsh(Writer& w, const MutableBitNameData& d)
{
    borsh_opt(w, d.commitment, [&](const Hash32& h) { w.raw(h); });
    borsh_opt(w, d.socket_addr_v4, [&](const SocketV4& s) { raw_v4(w, s); });
    borsh_opt(w, d.socket_addr_v6, [&](const SocketV6& s) { raw_v6(w, s); });
    borsh_opt(w, d.encryption_pubkey, [&](const bt::ByteArray<32>& k) { w.raw(k); });
    borsh_opt(w, d.signing_pubkey, [&](const bt::frost::Point& k) { w.raw(k); });
    borsh_opt(w, d.paymail_fee_sats, [&](uint64_t v) { w.u64(v); });
}

template <class T, class F>
static void borsh_update(Writer& w, const Update<T>& u, F f)
{
    w.u8(u.kind);
    if (u.kind == Update<T>::Set) f(u.value);
}

void borsh(Writer& w, const BitNameDataUpdates& u)
{
    borsh_update(w, u.commitment, [&](const Hash32& h) { w.raw(h); });
    borsh_update(w, u.socket_addr_v4, [&](const SocketV4& s) { raw_v4(w, s); });
    borsh_update(w, u.socket_addr_v6, [&](const SocketV6& s) { raw_v6(w, s); });
    borsh_update(w, u.encryption_pubkey, [&](const bt::ByteArray<32>& k) { w.raw(k); });
    borsh_update(w, u.signing_pubkey, [&](const bt::frost::Point& k) { w.raw(k); });
    borsh_update(w, u.paymail_fee_sats, [&](uint64_t v) { w.u64(v); });
}

void borsh(Writer& w, const TxData& d)
{
    w.u8(d.kind);
    switch (d.kind) {
    case TxData::Reservation: w.raw(d.commitment); break;
    case TxData::Registration:
        w.raw(d.name_hash);
        w.raw(d.revealed_nonce);
        borsh(w, d.data);
        break;
    case TxData::Update: borsh(w, d.updates); break;
    case TxData::BatchIcann:
        w.borsh_len(d.icann.plain_names.size());
        for (auto& n : d.icann.plain_names) w.borsh_bytes(ByteSpan((const uint8_t*)n.data(), n.size()));
        w.raw(d.icann.signature.R);
        w.raw(d.icann.signature.z);
        break;
    }
}

void borsh(Writer& w, const Transaction& t)
{
    w.borsh_len(t.inputs.size());
    for (auto& op : t.inputs) borsh(w, op);
    w.borsh_len(t.outputs.size());
    for (auto& o : t.outputs) borsh(w, o);
    w.borsh_bytes(t.memo);
    if (t.data) {
        w.u8(1);
        borsh(w, *t.data);
    } else {
        w.u8(0);
    }
}

void borsh(Writer& w, const Authorization& a)
{
    w.raw(a.verifying_key);
    w.raw(a.signature.R);
    w.raw(a.signature.z);
}

void borsh(Writer& w, const Coinbase& c)
{
    w.borsh_bytes(c.memo);
    w.borsh_len(c.outputs.size());
    for (auto& o : c.outputs) borsh(w, o);
}

void borsh(Writer& w, const Body& b)
{
    borsh(w, b.coinbase);
    w.borsh_len(b.transactions.size());
    for (auto& t : b.transactions) borsh(w, t);
    w.borsh_len(b.authorizations.size());
    for (auto& a : b.authorizations) borsh(w, a);
}

void borsh(Writer& w, const Header& h)
{
    w.raw(h.merkle_root);
    if (h.prev_side_hash) {
        w.u8(1);
        w.raw(*h.prev_side_hash);
    } else {
        w.u8(0);
    }
    w.raw(h.prev_main_hash);
}

// ---------------------------------------------------------------- borsh decode
// The borsh form carries only a withdrawal's scriptPubKey; recover the address of the same
// script (mainnet forms, as rust-bitcoin's from_script).
static bt::btc::Address address_from_spk(const Bytes& spk)
{
    bt::btc::Address a;
    if (spk.size() == 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14 && spk[23] == 0x88 && spk[24] == 0xac) {
        a.kind = bt::btc::Address::Kind::P2pkh;
        a.program.assign(spk.begin() + 3, spk.begin() + 23);
    } else if (spk.size() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87) {
        a.kind = bt::btc::Address::Kind::P2sh;
        a.program.assign(spk.begin() + 2, spk.begin() + 22);
    } else if (spk.size() >= 4 && (spk[0] == 0 || (spk[0] >= 0x51 && spk[0] <= 0x60)) && spk[1] + 2u == spk.size()) {
        a.kind = bt::btc::Address::Kind::Segwit;
        a.witver = spk[0] == 0 ? 0 : uint8_t(spk[0] - 0x50);
        a.program.assign(spk.begin() + 2, spk.end());
    } else {
        throw DecodeError("withdrawal script is not an address");
    }
    return a;
}

template <class T, class F>
static std::optional<T> borsh_de_opt(Reader& r, F f)
{
    uint8_t tag = r.u8();
    if (tag == 0) return std::nullopt;
    if (tag != 1) throw DecodeError("invalid Option tag");
    return f();
}

static SocketV4 de_v4(Reader& r)
{
    SocketV4 s;
    auto b = r.array<4>();
    std::memcpy(s.ip.data(), b.data(), 4);
    s.port = r.u16();
    return s;
}
static SocketV6 de_v6(Reader& r)
{
    SocketV6 s;
    auto b = r.array<16>();
    std::memcpy(s.ip.data(), b.data(), 16);
    s.port = r.u16();
    return s;
}
static bt::frost::Point de_vk_raw(Reader& r)
{
    auto p = r.array<32>();
    if (!bt::frost::valid_element(p)) throw DecodeError("invalid verifying key");
    return p;
}

static MutableBitNameData borsh_de_bitname_data(Reader& r)
{
    MutableBitNameData d;
    d.commitment = borsh_de_opt<Hash32>(r, [&] { return r.array<32>(); });
    d.socket_addr_v4 = borsh_de_opt<SocketV4>(r, [&] { return de_v4(r); });
    d.socket_addr_v6 = borsh_de_opt<SocketV6>(r, [&] { return de_v6(r); });
    d.encryption_pubkey = borsh_de_opt<bt::ByteArray<32>>(r, [&] { return r.array<32>(); });
    d.signing_pubkey = borsh_de_opt<bt::frost::Point>(r, [&] { return de_vk_raw(r); });
    d.paymail_fee_sats = borsh_de_opt<uint64_t>(r, [&] { return r.u64(); });
    return d;
}

template <class T, class F>
static Update<T> de_update(Reader& r, uint32_t tag, F f)
{
    Update<T> u;
    if (tag > 2) throw DecodeError("invalid Update tag");
    u.kind = typename Update<T>::Kind(tag);
    if (u.kind == Update<T>::Set) u.value = f();
    return u;
}

static BitNameDataUpdates borsh_de_updates(Reader& r)
{
    BitNameDataUpdates u;
    u.commitment = de_update<Hash32>(r, r.u8(), [&] { return r.array<32>(); });
    u.socket_addr_v4 = de_update<SocketV4>(r, r.u8(), [&] { return de_v4(r); });
    u.socket_addr_v6 = de_update<SocketV6>(r, r.u8(), [&] { return de_v6(r); });
    u.encryption_pubkey = de_update<bt::ByteArray<32>>(r, r.u8(), [&] { return r.array<32>(); });
    u.signing_pubkey = de_update<bt::frost::Point>(r, r.u8(), [&] { return de_vk_raw(r); });
    u.paymail_fee_sats = de_update<uint64_t>(r, r.u8(), [&] { return r.u64(); });
    return u;
}

static bt::frost::Signature de_sig64(ByteSpan b)
{
    bt::frost::Signature s;
    std::memcpy(s.R.data(), b.data(), 32);
    std::memcpy(s.z.data(), b.data() + 32, 32);
    if (!bt::frost::valid_element(s.R) || !bt::frost::canonical_scalar(s.z)) throw DecodeError("invalid signature encoding");
    return s;
}

Transaction borsh_de_transaction(Reader& r)
{
    Transaction t;
    size_t n = r.borsh_len(37);
    for (size_t i = 0; i < n; i++) {
        OutPoint o;
        uint8_t tag = r.u8();
        if (tag > 2) throw DecodeError("invalid OutPoint tag");
        o.kind = OutPoint::Kind(tag);
        o.txid = r.array<32>();
        o.vout = r.u32();
        t.inputs.push_back(o);
    }
    size_t m = r.borsh_len(25);
    for (size_t i = 0; i < m; i++) {
        Output o;
        o.address.b = r.array<20>();
        uint8_t tag = r.u8();
        switch (tag) {
        case 0: o.content.kind = Content::Bitcoin; o.content.value = r.u64(); break;
        case 1: o.content.kind = Content::BitName; break;
        case 2: o.content.kind = Content::BitNameReservation; break;
        case 3:
            o.content.kind = Content::Withdrawal;
            o.content.value = r.u64();
            o.content.main_fee = r.u64();
            o.content.main_address = address_from_spk(r.borsh_bytes());
            break;
        default: throw DecodeError("invalid Content tag");
        }
        o.memo = r.borsh_bytes();
        t.outputs.push_back(std::move(o));
    }
    t.memo = r.borsh_bytes();
    uint8_t has = r.u8();
    if (has == 1) {
        TxData d;
        uint8_t tag = r.u8();
        switch (tag) {
        case 0: d.kind = TxData::Reservation; d.commitment = r.array<32>(); break;
        case 1:
            d.kind = TxData::Registration;
            d.name_hash = r.array<32>();
            d.revealed_nonce = r.array<32>();
            d.data = borsh_de_bitname_data(r);
            break;
        case 2: d.kind = TxData::Update; d.updates = borsh_de_updates(r); break;
        case 3: {
            d.kind = TxData::BatchIcann;
            size_t k = r.borsh_len(4);
            for (size_t i = 0; i < k; i++) {
                Bytes s = r.borsh_bytes();
                std::string str(s.begin(), s.end());
                if (!Reader::utf8_valid(str)) throw DecodeError("invalid utf-8");
                d.icann.plain_names.push_back(str);
            }
            Bytes sig = r.raw(64);
            d.icann.signature = de_sig64(sig);
            break;
        }
        default: throw DecodeError("invalid TxData tag");
        }
        t.data = std::move(d);
    } else if (has != 0) {
        throw DecodeError("invalid Option tag");
    }
    return t;
}

// ---------------------------------------------------------------- bincode
static void bincode_withdrawal(Writer& w, uint64_t value, uint64_t main_fee, const bt::btc::Address& a)
{
    w.u64(value);
    w.u64(main_fee);
    w.bincode_str(a.to_string()); // Address<NetworkUnchecked> serde = Display string
}

void bincode(Writer& w, const Content& c)
{
    w.u32(c.kind); // DefaultRepr enum
    if (c.kind == Content::Bitcoin) w.u64(c.value);
    else if (c.kind == Content::Withdrawal) bincode_withdrawal(w, c.value, c.main_fee, c.main_address);
}

void bincode(Writer& w, const Output& o)
{
    w.raw(o.address.b);
    bincode(w, o.content);
    w.bincode_bytes(o.memo);
}

void bincode(Writer& w, const OutPoint& o)
{
    w.u32(o.kind);
    if (o.kind == OutPoint::Deposit) w.bincode_bytes(o.txid.span()); // bitcoin::Txid serde = bytes
    else w.raw(o.txid);
    w.u32(o.vout);
}

template <class T, class F>
static void bincode_opt(Writer& w, const std::optional<T>& v, F f)
{
    if (v) {
        w.u8(1);
        f(*v);
    } else {
        w.u8(0);
    }
}

void bincode(Writer& w, const MutableBitNameData& d)
{
    // serde: [u8; 32] tuples, SocketAddr (ip octets, port), x25519 MontgomeryPoint tuple,
    // frost VerifyingKey (serdect array) - all 32 raw bytes in bincode
    bincode_opt(w, d.commitment, [&](const Hash32& h) { w.raw(h); });
    bincode_opt(w, d.socket_addr_v4, [&](const SocketV4& s) { raw_v4(w, s); });
    bincode_opt(w, d.socket_addr_v6, [&](const SocketV6& s) { raw_v6(w, s); });
    bincode_opt(w, d.encryption_pubkey, [&](const bt::ByteArray<32>& k) { w.raw(k); });
    bincode_opt(w, d.signing_pubkey, [&](const bt::frost::Point& k) { w.raw(k); });
    bincode_opt(w, d.paymail_fee_sats, [&](uint64_t v) { w.u64(v); });
}

template <class T, class F>
static void bincode_update(Writer& w, const Update<T>& u, F f)
{
    w.u32(u.kind);
    if (u.kind == Update<T>::Set) f(u.value);
}

void bincode(Writer& w, const BitNameDataUpdates& u)
{
    bincode_update(w, u.commitment, [&](const Hash32& h) { w.raw(h); });
    bincode_update(w, u.socket_addr_v4, [&](const SocketV4& s) { raw_v4(w, s); });
    bincode_update(w, u.socket_addr_v6, [&](const SocketV6& s) { raw_v6(w, s); });
    bincode_update(w, u.encryption_pubkey, [&](const bt::ByteArray<32>& k) { w.raw(k); });
    bincode_update(w, u.signing_pubkey, [&](const bt::frost::Point& k) { w.raw(k); });
    bincode_update(w, u.paymail_fee_sats, [&](uint64_t v) { w.u64(v); });
}

void bincode(Writer& w, const TxData& d)
{
    w.u32(d.kind);
    switch (d.kind) {
    case TxData::Reservation: w.raw(d.commitment); break;
    case TxData::Registration:
        w.raw(d.name_hash);
        w.raw(d.revealed_nonce);
        bincode(w, d.data);
        break;
    case TxData::Update: bincode(w, d.updates); break;
    case TxData::BatchIcann:
        w.bincode_len(d.icann.plain_names.size());
        for (auto& n : d.icann.plain_names) w.bincode_str(n);
        w.bincode_len(64); // frost Signature: serdect slice
        w.raw(d.icann.signature.R);
        w.raw(d.icann.signature.z);
        break;
    }
}

void bincode(Writer& w, const Transaction& t)
{
    w.bincode_len(t.inputs.size());
    for (auto& op : t.inputs) bincode(w, op);
    w.bincode_len(t.outputs.size());
    for (auto& o : t.outputs) bincode(w, o);
    w.bincode_bytes(t.memo);
    if (t.data) {
        w.u8(1);
        bincode(w, *t.data);
    } else {
        w.u8(0);
    }
}

void bincode(Writer& w, const Authorization& a)
{
    w.raw(a.verifying_key); // serdect::array -> tuple, 32 bytes
    w.bincode_len(64);      // serdect::slice -> bytes with u64 length
    w.raw(a.signature.R);
    w.raw(a.signature.z);
}

void bincode(Writer& w, const AuthorizedTransaction& t)
{
    bincode(w, t.transaction);
    w.bincode_len(t.authorizations.size());
    for (auto& a : t.authorizations) bincode(w, a);
}

void bincode(Writer& w, const Coinbase& c)
{
    w.bincode_bytes(c.memo);
    w.bincode_len(c.outputs.size());
    for (auto& o : c.outputs) bincode(w, o);
}

void bincode(Writer& w, const Body& b)
{
    bincode(w, b.coinbase);
    w.bincode_len(b.transactions.size());
    for (auto& t : b.transactions) bincode(w, t);
    w.bincode_len(b.authorizations.size());
    for (auto& a : b.authorizations) bincode(w, a);
}

void bincode(Writer& w, const Header& h)
{
    w.raw(h.merkle_root);
    if (h.prev_side_hash) {
        w.u8(1);
        w.raw(*h.prev_side_hash);
    } else {
        w.u8(0);
    }
    w.bincode_bytes(h.prev_main_hash.span()); // bitcoin::BlockHash serde = bytes
}

void bincode(Writer& w, const FilledContent& c)
{
    w.u32(c.kind);
    switch (c.kind) {
    case FilledContent::Bitcoin: w.u64(c.value); break;
    case FilledContent::BitcoinWithdrawal: bincode_withdrawal(w, c.value, c.main_fee, c.main_address); break;
    case FilledContent::BitName: w.raw(c.bitname); break;
    case FilledContent::BitNameReservation:
        w.raw(c.reservation_txid);
        w.raw(c.reservation_commitment);
        break;
    }
}

void bincode(Writer& w, const FilledOutput& o)
{
    w.raw(o.address.b);
    bincode(w, o.content);
    w.bincode_bytes(o.memo);
}

static void de_withdrawal(Reader& r, uint64_t& value, uint64_t& main_fee, bt::btc::Address& a)
{
    value = r.u64();
    main_fee = r.u64();
    std::string s = r.bincode_str();
    auto p = bt::btc::Address::parse(s);
    if (!p) throw DecodeError("invalid main_address");
    a = *p;
}

Content de_content(Reader& r)
{
    Content c;
    uint32_t tag = r.u32();
    switch (tag) {
    case 0: c.kind = Content::Bitcoin; c.value = r.u64(); break;
    case 1: c.kind = Content::BitName; break;
    case 2: c.kind = Content::BitNameReservation; break;
    case 3: c.kind = Content::Withdrawal; de_withdrawal(r, c.value, c.main_fee, c.main_address); break;
    default: throw DecodeError("invalid Content tag");
    }
    return c;
}

Output de_output(Reader& r)
{
    Output o;
    o.address.b = r.array<20>();
    o.content = de_content(r);
    o.memo = r.bincode_bytes();
    return o;
}

OutPoint de_outpoint(Reader& r)
{
    OutPoint o;
    uint32_t tag = r.u32();
    if (tag > 2) throw DecodeError("invalid OutPoint tag");
    o.kind = OutPoint::Kind(tag);
    if (o.kind == OutPoint::Deposit) {
        Bytes b = r.bincode_bytes();
        if (b.size() != 32) throw DecodeError("invalid txid length");
        o.txid = Hash32::from_span(b);
    } else {
        o.txid = r.array<32>();
    }
    o.vout = r.u32();
    return o;
}

template <class T, class F>
static std::optional<T> de_opt(Reader& r, F f)
{
    uint8_t tag = r.u8();
    if (tag == 0) return std::nullopt;
    if (tag != 1) throw DecodeError("invalid Option tag");
    return f();
}

MutableBitNameData de_bitname_data(Reader& r)
{
    MutableBitNameData d;
    d.commitment = de_opt<Hash32>(r, [&] { return r.array<32>(); });
    d.socket_addr_v4 = de_opt<SocketV4>(r, [&] { return de_v4(r); });
    d.socket_addr_v6 = de_opt<SocketV6>(r, [&] { return de_v6(r); });
    d.encryption_pubkey = de_opt<bt::ByteArray<32>>(r, [&] { return r.array<32>(); });
    d.signing_pubkey = de_opt<bt::frost::Point>(r, [&] { return de_vk_raw(r); });
    d.paymail_fee_sats = de_opt<uint64_t>(r, [&] { return r.u64(); });
    return d;
}

static BitNameDataUpdates de_updates(Reader& r)
{
    BitNameDataUpdates u;
    u.commitment = de_update<Hash32>(r, r.u32(), [&] { return r.array<32>(); });
    u.socket_addr_v4 = de_update<SocketV4>(r, r.u32(), [&] { return de_v4(r); });
    u.socket_addr_v6 = de_update<SocketV6>(r, r.u32(), [&] { return de_v6(r); });
    u.encryption_pubkey = de_update<bt::ByteArray<32>>(r, r.u32(), [&] { return r.array<32>(); });
    u.signing_pubkey = de_update<bt::frost::Point>(r, r.u32(), [&] { return de_vk_raw(r); });
    u.paymail_fee_sats = de_update<uint64_t>(r, r.u32(), [&] { return r.u64(); });
    return u;
}

TxData de_txdata(Reader& r)
{
    TxData d;
    uint32_t tag = r.u32();
    switch (tag) {
    case 0: d.kind = TxData::Reservation; d.commitment = r.array<32>(); break;
    case 1:
        d.kind = TxData::Registration;
        d.name_hash = r.array<32>();
        d.revealed_nonce = r.array<32>();
        d.data = de_bitname_data(r);
        break;
    case 2: d.kind = TxData::Update; d.updates = de_updates(r); break;
    case 3: {
        d.kind = TxData::BatchIcann;
        size_t k = r.bincode_len(8);
        for (size_t i = 0; i < k; i++) d.icann.plain_names.push_back(r.bincode_str());
        Bytes sig = r.bincode_bytes();
        if (sig.size() != 64) throw DecodeError("MalformedSignature");
        d.icann.signature = de_sig64(sig);
        break;
    }
    default: throw DecodeError("invalid TxData tag");
    }
    return d;
}

Transaction de_transaction(Reader& r)
{
    Transaction t;
    size_t n = r.bincode_len(4 + 32 + 4);
    for (size_t i = 0; i < n; i++) t.inputs.push_back(de_outpoint(r));
    size_t m = r.bincode_len(20 + 4 + 8);
    for (size_t i = 0; i < m; i++) t.outputs.push_back(de_output(r));
    t.memo = r.bincode_bytes();
    t.data = de_opt<TxData>(r, [&] { return de_txdata(r); });
    return t;
}

Authorization de_authorization(Reader& r)
{
    Authorization a;
    a.verifying_key = r.array<32>();
    if (!bt::frost::valid_element(a.verifying_key)) throw DecodeError("invalid verifying key");
    Bytes sig = r.bincode_bytes();
    if (sig.size() != 64) throw DecodeError("MalformedSignature");
    a.signature = de_sig64(sig);
    return a;
}

AuthorizedTransaction de_authorized_transaction(Reader& r)
{
    AuthorizedTransaction t;
    t.transaction = de_transaction(r);
    size_t n = r.bincode_len(32 + 8 + 64);
    for (size_t i = 0; i < n; i++) t.authorizations.push_back(de_authorization(r));
    return t;
}

Coinbase de_coinbase(Reader& r)
{
    Coinbase c;
    c.memo = r.bincode_bytes();
    size_t n = r.bincode_len(20 + 4 + 8);
    for (size_t i = 0; i < n; i++) c.outputs.push_back(de_output(r));
    return c;
}

Body de_body(Reader& r)
{
    Body b;
    b.coinbase = de_coinbase(r);
    size_t n = r.bincode_len(8 + 8 + 8 + 1);
    for (size_t i = 0; i < n; i++) b.transactions.push_back(de_transaction(r));
    size_t m = r.bincode_len(32 + 8 + 64);
    for (size_t i = 0; i < m; i++) b.authorizations.push_back(de_authorization(r));
    return b;
}

Header de_header(Reader& r)
{
    Header h;
    h.merkle_root = r.array<32>();
    uint8_t opt = r.u8();
    if (opt == 1) h.prev_side_hash = r.array<32>();
    else if (opt != 0) throw DecodeError("invalid Option tag");
    Bytes pm = r.bincode_bytes();
    if (pm.size() != 32) throw DecodeError("invalid block hash length");
    h.prev_main_hash = Hash32::from_span(pm);
    return h;
}

FilledContent de_filled_content(Reader& r)
{
    FilledContent c;
    uint32_t tag = r.u32();
    switch (tag) {
    case 0: c.kind = FilledContent::Bitcoin; c.value = r.u64(); break;
    case 1: c.kind = FilledContent::BitcoinWithdrawal; de_withdrawal(r, c.value, c.main_fee, c.main_address); break;
    case 2: c.kind = FilledContent::BitName; c.bitname = r.array<32>(); break;
    case 3:
        c.kind = FilledContent::BitNameReservation;
        c.reservation_txid = r.array<32>();
        c.reservation_commitment = r.array<32>();
        break;
    default: throw DecodeError("invalid FilledContent tag");
    }
    return c;
}

FilledOutput de_filled_output(Reader& r)
{
    FilledOutput o;
    o.address.b = r.array<20>();
    o.content = de_filled_content(r);
    o.memo = r.bincode_bytes();
    return o;
}

// ---------------------------------------------------------------- merkle (merkle-cbt 0.3.2 CBMT)
namespace {
struct ValueNode {
    Hash32 commitment;
    uint64_t value = 0; // fees (txs) or output value (coinbase): bitcoin::Amount `+` panics on overflow
    uint64_t size = 0;  // canonical sizes: plain u64 `+`, wraps in release
};

std::optional<ValueNode> merge(const ValueNode& l, const ValueNode& r)
{
    ValueNode n;
    n.value = l.value + r.value;
    if (n.value < l.value) return std::nullopt;
    n.size = l.size + r.size;
    Writer w;
    w.raw(l.commitment);
    w.u64(n.value);
    w.u64(n.size);
    w.raw(r.commitment);
    n.commitment = bt::blake3(w.buf);
    return n;
}

// CBMT::build_merkle_root: pairs from the end (rchunks_exact), odd leaf to the front,
// then pop two from the front, push the parent to the back.
std::optional<ValueNode> cbmt_root(const std::vector<ValueNode>& leaves)
{
    if (leaves.empty()) return ValueNode{};
    std::deque<ValueNode> q;
    size_t i = leaves.size();
    while (i >= 2) {
        auto m = merge(leaves[i - 2], leaves[i - 1]);
        if (!m) return std::nullopt;
        q.push_back(*m);
        i -= 2;
    }
    if (i == 1) q.push_front(leaves[0]);
    while (q.size() > 1) {
        ValueNode right = q.front();
        q.pop_front();
        ValueNode left = q.front();
        q.pop_front();
        auto m = merge(left, right);
        if (!m) return std::nullopt;
        q.push_back(*m);
    }
    return q.front();
}

// Body::compute_merkle_root_levelized_parallel (types/lib.rs:801-850): from 1000 txs,
// duplicate the last node of every odd level and merge pairs left to right.
std::optional<ValueNode> levelized_root(std::vector<ValueNode> level)
{
    while (level.size() > 1) {
        if (level.size() % 2 == 1) level.push_back(level.back());
        std::vector<ValueNode> next;
        next.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            auto m = merge(level[i], level[i + 1]);
            if (!m) return std::nullopt;
            next.push_back(*m);
        }
        level = std::move(next);
    }
    return level.front();
}
} // namespace

std::optional<Hash32> coinbase_merkle_root(const Coinbase& cb)
{
    std::vector<ValueNode> leaves;
    for (auto& o : cb.outputs) {
        ValueNode n;
        n.value = o.get_value();
        Bytes ob = borsh_bytes(o);
        n.size = ob.size();
        Writer w;
        w.u64(n.value);
        w.u64(n.size);
        w.raw(ob);
        n.commitment = bt::blake3(w.buf);
        leaves.push_back(n);
    }
    auto r = cbmt_root(leaves);
    if (!r) return std::nullopt;
    Writer w;
    w.borsh_bytes(cb.memo);
    w.raw(r->commitment);
    return bt::blake3(w.buf);
}

std::optional<Hash32> compute_merkle_root(const Coinbase& cb, const std::vector<FilledTransaction>& txs)
{
    std::vector<ValueNode> leaves;
    leaves.reserve(txs.size());
    for (auto& ft : txs) {
        auto fee = ft.fee();
        if (!fee) return std::nullopt; // ComputeMerkleRootError::FeeComputation
        Bytes tb = ft.tx->canonical_bytes();
        Writer w;
        w.u64(*fee);
        w.u64(tb.size());
        w.raw(tb);
        leaves.push_back(ValueNode{bt::blake3(w.buf), *fee, tb.size()});
    }
    auto r = txs.size() >= MERKLE_LEVELIZED_FROM ? levelized_root(std::move(leaves)) : cbmt_root(leaves);
    if (!r) return std::nullopt;
    auto cbr = coinbase_merkle_root(cb);
    if (!cbr) return std::nullopt;
    Writer w;
    w.raw(*cbr);
    w.raw(r->commitment);
    return bt::blake3(w.buf);
}

// ---------------------------------------------------------------- authorizations
Bytes tx_signing_message(const Transaction& t)
{
    Bytes m{0}; // Dst::Transaction
    append(m, t.canonical_bytes());
    return m;
}

bool verify_with_dst(const bt::frost::Signature& sig, const bt::frost::Point& vk, uint8_t dst, ByteSpan msg)
{
    Bytes m{dst};
    append(m, msg);
    return bt::frost::verify(vk, sig, m);
}

bt::frost::Signature sign_with_dst(const bt::frost::SigningKey& sk, uint8_t dst, ByteSpan msg)
{
    Bytes m{dst};
    append(m, msg);
    return sk.sign(m);
}

bool verify_authorized_transaction(const AuthorizedTransaction& tx)
{
    if (tx.authorizations.size() != tx.transaction.inputs.size()) return false;
    if (tx.authorizations.empty()) return true; // "A BitName reservation can have no inputs"
    Bytes msg = tx_signing_message(tx.transaction);
    for (auto& a : tx.authorizations)
        if (!bt::frost::verify(a.verifying_key, a.signature, msg)) return false;
    return true;
}

bool verify_authorizations(const Body& body)
{
    if (body.authorizations.size() != body.inputs_len()) return false;
    size_t k = 0;
    for (auto& tx : body.transactions) {
        if (tx.inputs.empty()) continue;
        Bytes msg = tx_signing_message(tx);
        for (size_t i = 0; i < tx.inputs.size(); i++, k++) {
            auto& a = body.authorizations[k];
            if (!bt::frost::verify(a.verifying_key, a.signature, msg)) return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------- seq ids (types/bitname_seq_id.rs)
static constexpr uint32_t SEQ_DISPLAY_OFFSET = 23071990;

std::string seq_id_to_string(uint32_t seq)
{
    uint32_t first4 = seq / 100000000;
    uint32_t last8 = ((seq % 100000000) + SEQ_DISPLAY_OFFSET) % 100000000;
    char d[16];
    std::snprintf(d, sizeof(d), "%08u", last8);
    char r0[5] = {d[4], d[3], d[1], d[6], 0};
    char r1[5] = {d[2], d[7], d[0], d[5], 0};
    char out[32];
    if (first4 > 0) std::snprintf(out, sizeof(out), "%04u-%s-%s", first4, r0, r1);
    else std::snprintf(out, sizeof(out), "%s-%s", r0, r1);
    return out;
}

std::optional<uint32_t> seq_id_from_string(std::string_view s)
{
    std::vector<std::string_view> seg;
    for (char c : s)
        if (!(c >= '0' && c <= '9') && c != '-') return std::nullopt;
    if (s.empty() || s.front() == '-' || s.back() == '-') return std::nullopt;
    size_t i = 0;
    while (true) {
        size_t j = s.find('-', i);
        seg.push_back(s.substr(i, j == std::string_view::npos ? std::string_view::npos : j - i));
        if (j == std::string_view::npos) break;
        i = j + 1;
        if (seg.size() > 2) return std::nullopt;
    }
    for (auto& x : seg)
        if (x.size() != 4) return std::nullopt;
    if (seg.size() < 2 || seg.size() > 3) return std::nullopt;
    auto& s0 = seg[seg.size() - 2];
    auto& s1 = seg[seg.size() - 1];
    char d[9] = {s1[2], s0[2], s1[0], s0[1], s0[0], s1[3], s0[3], s1[1], 0};
    uint32_t v = uint32_t(std::strtoul(d, nullptr, 10));
    uint32_t last8 = v >= SEQ_DISPLAY_OFFSET ? v - SEQ_DISPLAY_OFFSET : 100000000 - (SEQ_DISPLAY_OFFSET - v);
    if (seg.size() == 2) return last8;
    uint64_t f = std::strtoul(std::string(seg[0]).c_str(), nullptr, 10) * 100000000ull;
    if (f > UINT32_MAX) return std::nullopt; // Overflow
    return uint32_t(uint32_t(f) + last8);   // unchecked `+` (wraps in release)
}

} // namespace bitnames
