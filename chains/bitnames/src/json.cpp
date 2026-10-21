// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <bitnames/json.h>

#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>

#include <bt/parse.h>

#include <cstring>

namespace bitnames::json {

static UniValue obj() { return UniValue(UniValue::VOBJ); }
static UniValue arr() { return UniValue(UniValue::VARR); }
static UniValue tagged(const std::string& k, const UniValue& v)
{
    UniValue r = obj();
    r.pushKV(k, v);
    return r;
}

UniValue hash(const Hash32& h) { return UniValue(bt::hex_encode(h)); }
UniValue btc_hash(const Hash32& h) { return UniValue(bt::hex_encode_rev(h.span())); }
UniValue bytes_array(ByteSpan b)
{
    UniValue a = arr();
    for (uint8_t x : b) a.push_back(UniValue(int(x)));
    return a;
}
UniValue address(const Address& a) { return UniValue(a.to_base58()); }

UniValue outpoint(const OutPoint& o)
{
    if (o.kind == OutPoint::Deposit) return tagged("Deposit", UniValue(bt::hex_encode_rev(o.txid.span()) + ":" + std::to_string(o.vout)));
    UniValue inner = obj();
    inner.pushKV("txid", hash(o.txid));
    inner.pushKV("vout", UniValue(uint64_t(o.vout)));
    return tagged(o.kind == OutPoint::Regular ? "Regular" : "Coinbase", inner);
}

static UniValue withdrawal(uint64_t value, uint64_t main_fee, const bt::btc::Address& a)
{
    UniValue w = obj();
    w.pushKV("value_sats", UniValue(value));
    w.pushKV("main_fee_sats", UniValue(main_fee));
    w.pushKV("main_address", a.to_string());
    return w;
}

UniValue content(const Content& c)
{
    switch (c.kind) {
    case Content::Bitcoin: return tagged("BitcoinSats", UniValue(c.value));
    case Content::BitName: return UniValue("BitName");
    case Content::BitNameReservation: return UniValue("BitNameReservation");
    case Content::Withdrawal: return tagged("Withdrawal", withdrawal(c.value, c.main_fee, c.main_address));
    }
    return UniValue();
}

UniValue filled_content(const FilledContent& c)
{
    switch (c.kind) {
    case FilledContent::Bitcoin: return tagged("BitcoinSats", UniValue(c.value));
    case FilledContent::BitcoinWithdrawal: return tagged("BitcoinWithdrawal", withdrawal(c.value, c.main_fee, c.main_address));
    case FilledContent::BitName: return tagged("BitName", hash(c.bitname));
    case FilledContent::BitNameReservation: {
        UniValue p = arr();
        p.push_back(hash(c.reservation_txid));
        p.push_back(UniValue("0x" + bt::hex_encode(c.reservation_commitment))); // const_hex::serde: 0x-prefixed
        return tagged("BitNameReservation", p);
    }
    }
    return UniValue();
}

UniValue output(const Output& o)
{
    UniValue r = obj();
    r.pushKV("address", address(o.address));
    r.pushKV("content", content(o.content));
    r.pushKV("memo", bt::hex_encode(o.memo));
    return r;
}

UniValue filled_output(const FilledOutput& o)
{
    UniValue r = obj();
    r.pushKV("address", address(o.address));
    r.pushKV("content", filled_content(o.content));
    r.pushKV("memo", bt::hex_encode(o.memo));
    return r;
}

UniValue inpoint(const InPoint& i)
{
    UniValue x = obj();
    if (i.kind == InPoint::Regular) {
        x.pushKV("txid", hash(i.id));
        x.pushKV("vin", UniValue(uint64_t(i.vin)));
        return tagged("Regular", x);
    }
    x.pushKV("m6id", btc_hash(i.id));
    return tagged("Withdrawal", x);
}

UniValue spent_output(const SpentOutput& s)
{
    UniValue r = obj();
    r.pushKV("output", filled_output(s.output));
    r.pushKV("inpoint", inpoint(s.inpoint));
    return r;
}

UniValue pointed(const OutPoint& op, const UniValue& o)
{
    UniValue r = obj();
    r.pushKV("outpoint", outpoint(op));
    r.pushKV("output", o);
    return r;
}

template <class T, class F>
static UniValue opt(const std::optional<T>& v, F f)
{
    return v ? f(*v) : UniValue();
}

static void push_mutable(UniValue& r, const MutableBitNameData& d)
{
    r.pushKV("commitment", opt(d.commitment, [](const Hash32& h) { return bytes_array(h.span()); }));
    r.pushKV("socket_addr_v4", opt(d.socket_addr_v4, [](const SocketV4& s) { return UniValue(s.to_string()); }));
    r.pushKV("socket_addr_v6", opt(d.socket_addr_v6, [](const SocketV6& s) { return UniValue(s.to_string()); }));
    r.pushKV("encryption_pubkey", opt(d.encryption_pubkey, [](const bt::ByteArray<32>& k) { return UniValue(epk_to_string(k)); }));
    r.pushKV("signing_pubkey", opt(d.signing_pubkey, [](const bt::frost::Point& k) { return UniValue(vk_to_string(k)); }));
    r.pushKV("paymail_fee_sats", opt(d.paymail_fee_sats, [](uint64_t v) { return UniValue(v); }));
}

UniValue mutable_data(const MutableBitNameData& d)
{
    UniValue r = obj();
    push_mutable(r, d);
    return r;
}

UniValue bitname_data(const BitNameData& d)
{
    UniValue r = obj();
    r.pushKV("seq_id", seq_id_to_string(d.seq_id));
    push_mutable(r, d.data);
    return r;
}

template <class T, class F>
static UniValue update(const Update<T>& u, F f)
{
    if (u.kind == Update<T>::Delete) return UniValue("Delete");
    if (u.kind == Update<T>::Retain) return UniValue("Retain");
    return tagged("Set", f(u.value));
}

UniValue updates(const BitNameDataUpdates& u)
{
    UniValue r = obj();
    r.pushKV("commitment", update(u.commitment, [](const Hash32& h) { return bytes_array(h.span()); }));
    r.pushKV("socket_addr_v4", update(u.socket_addr_v4, [](const SocketV4& s) { return UniValue(s.to_string()); }));
    r.pushKV("socket_addr_v6", update(u.socket_addr_v6, [](const SocketV6& s) { return UniValue(s.to_string()); }));
    r.pushKV("encryption_pubkey", update(u.encryption_pubkey, [](const bt::ByteArray<32>& k) { return UniValue(epk_to_string(k)); }));
    r.pushKV("signing_pubkey", update(u.signing_pubkey, [](const bt::frost::Point& k) { return UniValue(vk_to_string(k)); }));
    r.pushKV("paymail_fee_sats", update(u.paymail_fee_sats, [](uint64_t v) { return UniValue(v); }));
    return r;
}

UniValue signature(const bt::frost::Signature& s)
{
    Bytes b(s.R.begin(), s.R.end());
    b.insert(b.end(), s.z.begin(), s.z.end());
    return UniValue("0x" + bt::hex_encode(b)); // const_hex: 0x-prefixed
}

UniValue txdata(const TxData& d)
{
    switch (d.kind) {
    case TxData::Reservation: {
        UniValue x = obj();
        x.pushKV("commitment", hash(d.commitment));
        return tagged("BitNameReservation", x);
    }
    case TxData::Registration: {
        UniValue x = obj();
        x.pushKV("name_hash", hash(d.name_hash));
        x.pushKV("revealed_nonce", hash(d.revealed_nonce));
        x.pushKV("bitname_data", mutable_data(d.data));
        return tagged("BitNameRegistration", x);
    }
    case TxData::Update: return tagged("BitNameUpdate", updates(d.updates));
    case TxData::BatchIcann: {
        UniValue x = obj();
        UniValue names = arr();
        for (auto& n : d.icann.plain_names) names.push_back(n);
        x.pushKV("plain_names", names);
        x.pushKV("signature", signature(d.icann.signature));
        return tagged("BatchIcann", x);
    }
    }
    return UniValue();
}

UniValue transaction(const Transaction& t)
{
    UniValue r = obj();
    UniValue ins = arr();
    for (auto& op : t.inputs) ins.push_back(outpoint(op));
    r.pushKV("inputs", ins);
    UniValue outs = arr();
    for (auto& o : t.outputs) outs.push_back(output(o));
    r.pushKV("outputs", outs);
    r.pushKV("memo", bt::hex_encode(t.memo));
    r.pushKV("data", t.data ? txdata(*t.data) : UniValue());
    return r;
}

UniValue authorization(const Authorization& a)
{
    UniValue r = obj();
    r.pushKV("verifying_key", vk_to_string(a.verifying_key));
    r.pushKV("signature", signature(a.signature));
    return r;
}

UniValue authorized_transaction(const AuthorizedTransaction& t)
{
    UniValue r = obj();
    r.pushKV("transaction", transaction(t.transaction));
    UniValue a = arr();
    for (auto& x : t.authorizations) a.push_back(authorization(x));
    r.pushKV("authorizations", a);
    return r;
}

UniValue coinbase(const Coinbase& c)
{
    UniValue r = obj();
    r.pushKV("memo", bt::hex_encode(c.memo));
    UniValue o = arr();
    for (auto& x : c.outputs) o.push_back(output(x));
    r.pushKV("outputs", o);
    return r;
}

UniValue body(const Body& b)
{
    UniValue r = obj();
    r.pushKV("coinbase", coinbase(b.coinbase));
    UniValue txs = arr();
    for (auto& t : b.transactions) txs.push_back(transaction(t));
    r.pushKV("transactions", txs);
    UniValue a = arr();
    for (auto& x : b.authorizations) a.push_back(authorization(x));
    r.pushKV("authorizations", a);
    return r;
}

UniValue header(const Header& h)
{
    UniValue r = obj();
    r.pushKV("merkle_root", hash(h.merkle_root));
    r.pushKV("prev_side_hash", h.prev_side_hash ? hash(*h.prev_side_hash) : UniValue());
    r.pushKV("prev_main_hash", btc_hash(h.prev_main_hash));
    return r;
}

UniValue block(const Header& h, const Body& b, uint32_t height)
{
    UniValue r = obj();
    r.pushKV("header", header(h));
    r.pushKV("body", body(b));
    r.pushKV("height", UniValue(uint64_t(height)));
    return r;
}

UniValue bitcoin_tx(const std::vector<bt::btc::TxOut>& outs)
{
    UniValue r = obj();
    r.pushKV("version", 2);
    r.pushKV("lock_time", 0);
    r.pushKV("input", arr());
    UniValue o = arr();
    for (auto& x : outs) {
        UniValue t = obj();
        t.pushKV("value", UniValue(x.value));
        t.pushKV("script_pubkey", bt::hex_encode(x.script_pubkey));
        o.push_back(t);
    }
    r.pushKV("output", o);
    return r;
}

UniValue withdrawal_bundle(const WithdrawalBundle& w)
{
    UniValue r = obj();
    UniValue su = arr();
    for (auto& [op, o] : w.spend_utxos) {
        UniValue p = arr();
        p.push_back(outpoint(op));
        p.push_back(filled_output(o));
        su.push_back(p);
    }
    r.pushKV("spend_utxos", su);
    r.pushKV("tx", bitcoin_tx(w.outputs));
    return r;
}

// ------------------------------------------------------------------ parsing
std::string serde_unexpected(const UniValue& v)
{
    if (v.isNull()) return "null";
    if (v.isBool()) return std::string("boolean `") + (v.get_bool() ? "true" : "false") + "`";
    if (v.isArray()) return "sequence";
    if (v.isObject()) return "map";
    if (v.isStr()) {
        // Rust's Debug of a str.
        std::string r = "string \"";
        for (unsigned char ch : v.get_str()) {
            if (ch == '"') r += "\\\"";
            else if (ch == '\\') r += "\\\\";
            else if (ch == '\n') r += "\\n";
            else if (ch == '\t') r += "\\t";
            else if (ch == '\r') r += "\\r";
            else if (ch < 0x20 || ch == 0x7f) {
                char b[16];
                std::snprintf(b, sizeof(b), "\\u{%x}", ch);
                r += b;
            } else r += char(ch);
        }
        return r + "\"";
    }
    const std::string& s = v.getValStr();
    if (s.find_first_of(".eE") != std::string::npos) {
        // serde_json reads it as an f64; Rust's Display of an f64: the shortest form, no ".0" when integral.
        double d = std::strtod(s.c_str(), nullptr);
        char b[64];
        for (int prec = 1; prec <= 17; prec++) {
            std::snprintf(b, sizeof(b), "%.*g", prec, d);
            if (std::strtod(b, nullptr) == d) break;
        }
        std::string f = b;
        if (f.find('e') != std::string::npos && d == std::floor(d)) {
            std::snprintf(b, sizeof(b), "%.0f", d);
            f = b;
        }
        return "floating point `" + f + "`";
    }
    return "integer `" + s + "`";
}

static uint64_t parse_uint(const UniValue& v, uint64_t max, const char* type)
{
    if (!v.isNum()) throw Error("invalid type: " + serde_unexpected(v) + ", expected " + type, &v);
    const std::string& s = v.getValStr();
    if (s.find_first_of(".eE") != std::string::npos) throw Error("invalid type: " + serde_unexpected(v) + ", expected " + type, &v);
    auto x = s.empty() || s[0] == '-' ? std::nullopt : bt::parse_u64(s);
    if (!x || *x > max) throw Error("invalid value: " + serde_unexpected(v) + ", expected " + type, &v);
    return *x;
}

uint64_t parse_u64(const UniValue& v) { return parse_uint(v, UINT64_MAX, "u64"); }
uint32_t parse_u32(const UniValue& v) { return uint32_t(parse_uint(v, UINT32_MAX, "u32")); }

void require_struct(const UniValue& v, const char* name, std::initializer_list<const char*> fields)
{
    if (!v.isObject()) throw Error("invalid type: " + serde_unexpected(v) + ", expected struct " + name, &v);
    for (const char* f : fields)
        if (!v.exists(f)) throw Error(std::string("missing field `") + f + "`", &v);
}

Bytes parse_hex(const UniValue& v)
{
    if (!v.isStr()) throw Error("expected a hex string", &v);
    auto b = bt::hex_decode(v.get_str());
    if (!b) throw Error("invalid hex", &v);
    return *b;
}

// const-hex's decode_to_array, which the 32-byte hashes' serde uses: an optional 0x prefix, then an odd length,
// the length, the first character that is not hex, in its words.
static std::string rust_char_debug(unsigned char b)
{
    switch (b) {
    case 0: return "'\\0'";
    case '\t': return "'\\t'";
    case '\n': return "'\\n'";
    case '\r': return "'\\r'";
    case '\'': return "'\\''";
    case '\\': return "'\\\\'";
    }
    char buf[16];
    if (b < 0x20 || b == 0x7f) {
        std::snprintf(buf, sizeof(buf), "'\\u{%x}'", b);
        return buf;
    }
    if (b < 0x80) return std::string("'") + char(b) + "'";
    return std::string("'") + char(0xc0 | (b >> 6)) + char(0x80 | (b & 0x3f)) + "'";
}

Hash32 parse_hash(const UniValue& v)
{
    if (!v.isStr()) throw Error("expected a hex string", &v);
    std::string s = v.get_str();
    if (s.rfind("0x", 0) == 0) s = s.substr(2);
    if (s.size() % 2) throw Error("odd number of digits", &v);
    if (s.size() != 64) throw Error("invalid string length", &v);
    for (size_t i = 0; i < s.size(); i++)
        if (!std::isxdigit((unsigned char)s[i])) throw Error("invalid character " + rust_char_debug((unsigned char)s[i]) + " at position " + std::to_string(i), &v);
    auto h = bt::hex_to_array<32>(s);
    if (!h) throw Error("invalid hash", &v);
    return *h;
}
Hash32 parse_btc_hash(const UniValue& v)
{
    if (!v.isStr()) throw Error("expected a hex string", &v);
    auto h = bt::hash_from_rev_hex(v.get_str());
    if (!h) throw Error("invalid hash", &v);
    return *h;
}
Address parse_address(const UniValue& v)
{
    if (!v.isStr()) throw Error("expected an address string", &v);
    // plain_bitnames_types::ParseAddress: "bs58 error", or "wrong address length {n} != 20".
    auto d = bt::base58_decode(v.get_str());
    if (!d) throw Error("bs58 error", &v);
    if (d->size() != 20) throw Error("wrong address length " + std::to_string(d->size()) + " != 20", &v);
    auto a = Address::from_base58(v.get_str());
    if (!a) throw Error("invalid address", &v);
    return *a;
}
bt::btc::Address parse_btc_address(const UniValue& v)
{
    if (!v.isStr()) throw Error("expected a bitcoin address", &v);
    auto a = bt::btc::Address::parse(v.get_str());
    // rust-bitcoin 0.32 falls back to base58 when bech32 does not decode: "base58 error".
    if (!a) throw Error(bt::base58check_decode(v.get_str()) ? "invalid bitcoin address" : "base58 error", &v);
    return *a;
}

static Hash32 parse_byte_array32(const UniValue& v)
{
    if (!v.isArray() || v.size() != 32) throw Error("expected an array of 32 bytes", &v);
    Hash32 h;
    for (size_t i = 0; i < 32; i++) {
        uint64_t b = parse_u64(v[i]);
        if (b > 255) throw Error("byte out of range", &v);
        h[i] = uint8_t(b);
    }
    return h;
}

OutPoint parse_outpoint(const UniValue& v)
{
    if (!v.isObject() || v.size() != 1) throw Error("invalid OutPoint", &v);
    const std::string& k = v.getKeys()[0];
    const UniValue& x = v.getValues()[0];
    OutPoint o;
    if (k == "Deposit") {
        if (!x.isStr()) throw Error("invalid deposit outpoint", &v);
        auto s = x.get_str();
        auto c = s.rfind(':');
        if (c == std::string::npos) throw Error("invalid deposit outpoint", &v);
        o.kind = OutPoint::Deposit;
        o.txid = parse_btc_hash(UniValue(s.substr(0, c)));
        auto vout = bt::parse_u64(s.substr(c + 1));
        if (!vout || *vout > UINT32_MAX) throw Error("invalid deposit outpoint", &v);
        o.vout = uint32_t(*vout);
        return o;
    }
    if (k != "Regular" && k != "Coinbase") throw Error("invalid OutPoint variant", &v);
    o.kind = k == "Regular" ? OutPoint::Regular : OutPoint::Coinbase;
    o.txid = parse_hash(x["txid"]);
    o.vout = parse_u32(x["vout"]);
    return o;
}

static Content parse_content(const UniValue& c)
{
    Content r;
    if (c.isStr()) {
        if (c.get_str() == "BitName") r.kind = Content::BitName;
        else if (c.get_str() == "BitNameReservation") r.kind = Content::BitNameReservation;
        else throw Error("invalid content variant", &v);
        return r;
    }
    if (!c.isObject() || c.size() != 1) throw Error("invalid content", &v);
    const std::string& k = c.getKeys()[0];
    const UniValue& x = c.getValues()[0];
    if (k == "BitcoinSats") {
        r.kind = Content::Bitcoin;
        r.value = parse_u64(x);
    } else if (k == "Withdrawal") {
        r.kind = Content::Withdrawal;
        r.value = parse_u64(x["value_sats"]);
        r.main_fee = parse_u64(x["main_fee_sats"]);
        r.main_address = parse_btc_address(x["main_address"]);
    } else {
        throw Error("invalid content variant", &v);
    }
    return r;
}

Output parse_output(const UniValue& v)
{
    if (!v.isObject()) throw Error("invalid output", &v);
    Output o;
    o.address = parse_address(v["address"]);
    o.content = parse_content(v["content"]);
    o.memo = parse_hex(v["memo"]);
    return o;
}

bt::frost::Point parse_vk(const UniValue& v)
{
    if (!v.isStr()) throw Error("expected a verifying key", &v);
    auto k = vk_from_string(v.get_str());
    if (!k) throw Error("invalid verifying key", &v);
    return *k;
}

bt::ByteArray<32> parse_epk(const UniValue& v)
{
    if (!v.isStr()) throw Error("expected an encryption pubkey", &v);
    auto k = epk_from_string(v.get_str());
    if (!k) throw Error("parsing failed", &v); // their EncryptionPubKey's FromStr error
    return *k;
}

static SocketV4 parse_v4(const UniValue& v)
{
    if (!v.isStr()) throw Error("expected a socket address", &v);
    auto s = SocketV4::parse(v.get_str());
    if (!s) throw Error("invalid socket address", &v);
    return *s;
}
static SocketV6 parse_v6(const UniValue& v)
{
    if (!v.isStr()) throw Error("expected a socket address", &v);
    auto s = SocketV6::parse(v.get_str());
    if (!s) throw Error("invalid socket address", &v);
    return *s;
}

MutableBitNameData parse_mutable_data(const UniValue& v)
{
    MutableBitNameData d;
    if (v.isNull()) return d;
    if (!v.isObject()) throw Error("invalid bitname data", &v);
    auto f = [&](const char* k) -> const UniValue* {
        const UniValue& x = v[k];
        return x.isNull() ? nullptr : &x;
    };
    if (auto x = f("commitment")) d.commitment = parse_byte_array32(*x);
    if (auto x = f("socket_addr_v4")) d.socket_addr_v4 = parse_v4(*x);
    if (auto x = f("socket_addr_v6")) d.socket_addr_v6 = parse_v6(*x);
    if (auto x = f("encryption_pubkey")) d.encryption_pubkey = parse_epk(*x);
    if (auto x = f("signing_pubkey")) d.signing_pubkey = parse_vk(*x);
    if (auto x = f("paymail_fee_sats")) d.paymail_fee_sats = parse_u64(*x);
    return d;
}

template <class T, class F>
static Update<T> parse_update(const UniValue& v, F f)
{
    Update<T> u;
    if (v.isStr()) {
        if (v.get_str() == "Delete") u.kind = Update<T>::Delete;
        else if (v.get_str() == "Retain") u.kind = Update<T>::Retain;
        else throw Error("invalid update", &v);
        return u;
    }
    if (!v.isObject() || v.size() != 1 || v.getKeys()[0] != "Set") throw Error("invalid update", &v);
    u.kind = Update<T>::Set;
    u.value = f(v.getValues()[0]);
    return u;
}

bt::frost::Signature parse_signature(const UniValue& v)
{
    // const_hex: an optional 0x prefix (theirs writes it).
    Bytes b = parse_hex(v.isStr() && v.get_str().rfind("0x", 0) == 0 ? UniValue(v.get_str().substr(2)) : v);
    if (b.size() != 64) throw Error("invalid signature length", &v);
    bt::frost::Signature s;
    std::memcpy(s.R.data(), b.data(), 32);
    std::memcpy(s.z.data(), b.data() + 32, 32);
    if (!bt::frost::valid_element(s.R) || !bt::frost::canonical_scalar(s.z)) throw Error("invalid signature encoding", &v);
    return s;
}

TxData parse_txdata(const UniValue& v)
{
    if (!v.isObject() || v.size() != 1) throw Error("invalid transaction data", &v);
    const std::string& k = v.getKeys()[0];
    const UniValue& x = v.getValues()[0];
    TxData d;
    if (k == "BitNameReservation") {
        d.kind = TxData::Reservation;
        d.commitment = parse_hash(x["commitment"]);
    } else if (k == "BitNameRegistration") {
        d.kind = TxData::Registration;
        d.name_hash = parse_hash(x["name_hash"]);
        d.revealed_nonce = parse_hash(x["revealed_nonce"]);
        d.data = parse_mutable_data(x["bitname_data"]);
    } else if (k == "BitNameUpdate") {
        d.kind = TxData::Update;
        d.updates.commitment = parse_update<Hash32>(x["commitment"], parse_byte_array32);
        d.updates.socket_addr_v4 = parse_update<SocketV4>(x["socket_addr_v4"], parse_v4);
        d.updates.socket_addr_v6 = parse_update<SocketV6>(x["socket_addr_v6"], parse_v6);
        d.updates.encryption_pubkey = parse_update<bt::ByteArray<32>>(x["encryption_pubkey"], parse_epk);
        d.updates.signing_pubkey = parse_update<bt::frost::Point>(x["signing_pubkey"], parse_vk);
        d.updates.paymail_fee_sats = parse_update<uint64_t>(x["paymail_fee_sats"], [](const UniValue& y) { return parse_u64(y); });
    } else if (k == "BatchIcann") {
        d.kind = TxData::BatchIcann;
        for (auto& n : x["plain_names"].getValues()) {
            if (!n.isStr()) throw Error("invalid plain name", &v);
            d.icann.plain_names.push_back(n.get_str());
        }
        d.icann.signature = parse_signature(x["signature"]);
    } else {
        throw Error("invalid transaction data variant", &v);
    }
    return d;
}

Transaction parse_transaction(const UniValue& v)
{
    require_struct(v, "Transaction", {"inputs", "outputs", "memo"});
    Transaction t;
    for (auto& in : v["inputs"].getValues()) t.inputs.push_back(parse_outpoint(in));
    for (auto& o : v["outputs"].getValues()) t.outputs.push_back(parse_output(o));
    t.memo = parse_hex(v["memo"]);
    if (!v["data"].isNull()) t.data = parse_txdata(v["data"]);
    return t;
}

static Authorization parse_authorization(const UniValue& v)
{
    if (!v.isObject()) throw Error("invalid authorization", &v);
    return Authorization{parse_vk(v["verifying_key"]), parse_signature(v["signature"])};
}

AuthorizedTransaction parse_authorized_transaction(const UniValue& v)
{
    require_struct(v, "Authorized", {"transaction", "authorizations"});
    AuthorizedTransaction t;
    t.transaction = parse_transaction(v["transaction"]);
    for (auto& a : v["authorizations"].getValues()) t.authorizations.push_back(parse_authorization(a));
    return t;
}

Header parse_header(const UniValue& v)
{
    require_struct(v, "Header", {"merkle_root", "prev_main_hash"});
    Header h;
    h.merkle_root = parse_hash(v["merkle_root"]);
    if (!v["prev_side_hash"].isNull()) h.prev_side_hash = parse_hash(v["prev_side_hash"]);
    h.prev_main_hash = parse_btc_hash(v["prev_main_hash"]);
    return h;
}

Body parse_body(const UniValue& v)
{
    require_struct(v, "Body", {"coinbase", "transactions", "authorizations"});
    Body b;
    const UniValue& cb = v["coinbase"];
    b.coinbase.memo = parse_hex(cb["memo"]);
    for (auto& o : cb["outputs"].getValues()) b.coinbase.outputs.push_back(parse_output(o));
    for (auto& t : v["transactions"].getValues()) b.transactions.push_back(parse_transaction(t));
    for (auto& a : v["authorizations"].getValues()) b.authorizations.push_back(parse_authorization(a));
    return b;
}

} // namespace bitnames::json
