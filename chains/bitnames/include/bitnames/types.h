// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// BitNames (eCash betanet slot 2) consensus types, byte-exact with the octobocto fork of
// plain-bitnames at v0.18.2 (7b4c309; v0.18.0-0.18.2 share these rules), which is what the
// betanet chain runs. Every hash is BLAKE3(borsh(x)); the P2P wire uses bincode 1.3 over
// serde (non-human-readable forms). Citations are fork paths at v0.18.2.
//
// Fork deltas over upstream 0.17.2 that change bytes: Coinbase{memo, outputs} with its own
// merkle tree and CoinbaseTxid outpoints, canonical_size in bytes, FROST-ristretto255
// authorizations (message = 0x00 || borsh(tx)), the `s2_<b58>_<hex>` deposit address form.
#pragma once

#include <bt/bitcoin.h>
#include <bt/bytes.h>
#include <bt/codec.h>
#include <bt/crypto.h>
#include <bt/frost.h>

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace bitnames {

using bt::Bytes;
using bt::append;
using bt::ByteSpan;
using bt::Hash32;
using bt::Reader;
using bt::Writer;

constexpr uint8_t THIS_SIDECHAIN = 2; // types/lib.rs:55

/** types/address.rs: 20 raw bytes, text = plain base58, no version, no checksum. */
struct Address {
    bt::Hash20 b;
    static const Address ALL_ZEROS;
    std::string to_base58() const;
    static std::optional<Address> from_base58(std::string_view s);
    /** `s2_<b58>_<hex(sha256(prefix))[..6]>` (address.rs format_for_deposit). */
    std::string format_for_deposit() const;
    /** address.rs from_deposit_address: "s2_" prefix, rsplit at the last '_', any non-empty
     *  case-insensitive hex prefix of sha256("s2_<addr>_") as checksum, then base58. */
    static std::optional<Address> from_deposit_address(std::string_view s);
    friend auto operator<=>(const Address&, const Address&) = default;
    friend bool operator==(const Address&, const Address&) = default;
};

/** authorization.rs get_address: first 20 bytes of BLAKE3-XOF(compressed VK). */
Address address_from_vk(const bt::frost::Point& vk);

/** VerifyingKey text form: Bech32m "bn-svk" (keys.rs); nullopt also for invalid points. */
std::string vk_to_string(const bt::frost::Point& vk);
std::optional<bt::frost::Point> vk_from_string(std::string_view s);
/** EncryptionPubKey (x25519) text form: Bech32m "bn-enc". */
std::string epk_to_string(const bt::ByteArray<32>& k);
std::optional<bt::ByteArray<32>> epk_from_string(std::string_view s);

/** std::net::SocketAddrV4 / V6 as borsh and serde-bincode write them: address octets then
 *  the port as u16 LE (V6 flowinfo and scope id are not encoded). */
struct SocketV4 {
    std::array<uint8_t, 4> ip{};
    uint16_t port = 0;
    bool operator==(const SocketV4&) const = default;
    std::string to_string() const;
    static std::optional<SocketV4> parse(std::string_view s);
};
struct SocketV6 {
    std::array<uint8_t, 16> ip{};
    uint16_t port = 0;
    bool operator==(const SocketV6&) const = default;
    std::string to_string() const;
    static std::optional<SocketV6> parse(std::string_view s);
};

/** types/bitname_data.rs MutableBitNameData: six optional fields in this order. */
struct MutableBitNameData {
    std::optional<Hash32> commitment;
    std::optional<SocketV4> socket_addr_v4;
    std::optional<SocketV6> socket_addr_v6;
    std::optional<bt::ByteArray<32>> encryption_pubkey; // x25519
    std::optional<bt::frost::Point> signing_pubkey;     // FROST ristretto255 verifying key
    std::optional<uint64_t> paymail_fee_sats;
    bool operator==(const MutableBitNameData&) const = default;
};

/** Update<T> = Delete | Retain | Set(T). */
template <class T>
struct Update {
    enum Kind : uint8_t { Delete = 0, Retain = 1, Set = 2 } kind = Retain;
    T value{};
};

struct BitNameDataUpdates {
    Update<Hash32> commitment;
    Update<SocketV4> socket_addr_v4;
    Update<SocketV6> socket_addr_v6;
    Update<bt::ByteArray<32>> encryption_pubkey;
    Update<bt::frost::Point> signing_pubkey;
    Update<uint64_t> paymail_fee_sats;
};

struct BatchIcannData {
    std::vector<std::string> plain_names;
    bt::frost::Signature signature;
};

/** transaction/mod.rs TransactionData. */
struct TxData {
    enum Kind : uint8_t { Reservation = 0, Registration = 1, Update = 2, BatchIcann = 3 } kind = Reservation;
    Hash32 commitment;          // Reservation
    Hash32 name_hash;           // Registration
    Hash32 revealed_nonce;      // Registration
    MutableBitNameData data;    // Registration
    BitNameDataUpdates updates; // Update
    BatchIcannData icann;       // BatchIcann
};

/** transaction/output_content.rs Content. */
struct Content {
    enum Kind : uint8_t { Bitcoin = 0, BitName = 1, BitNameReservation = 2, Withdrawal = 3 } kind = Bitcoin;
    uint64_t value = 0;            // Bitcoin / Withdrawal
    uint64_t main_fee = 0;         // Withdrawal
    bt::btc::Address main_address; // Withdrawal
    /** Withdrawal = value + main_fee saturating; names and reservations carry no value. */
    uint64_t get_value() const;
    bool operator==(const Content& o) const;
};

struct Output {
    Address address;
    Content content;
    Bytes memo;
    uint64_t get_value() const { return content.get_value(); }
    bool operator==(const Output&) const = default;
};

/** FilledContent: what an output holds once its tokens are known. */
struct FilledContent {
    enum Kind : uint8_t { Bitcoin = 0, BitcoinWithdrawal = 1, BitName = 2, BitNameReservation = 3 } kind = Bitcoin;
    uint64_t value = 0;
    uint64_t main_fee = 0;
    bt::btc::Address main_address;
    Hash32 bitname;            // BitName
    Hash32 reservation_txid;   // BitNameReservation
    Hash32 reservation_commitment;
    uint64_t get_value() const;
    bool is_withdrawal() const { return kind == BitcoinWithdrawal; }
    bool is_bitname() const { return kind == BitName; }
    bool is_reservation() const { return kind == BitNameReservation; }
    Content to_content() const;
    bool operator==(const FilledContent& o) const;
};

struct FilledOutput {
    Address address;
    FilledContent content;
    Bytes memo;
    uint64_t get_value() const { return content.get_value(); }
    Output to_output() const { return Output{address, content.to_content(), memo}; }
    bool operator==(const FilledOutput&) const = default;
};

/** transaction/mod.rs OutPoint. Ord = variant index, then (txid bytes, vout). */
struct OutPoint {
    enum Kind : uint8_t { Regular = 0, Coinbase = 1, Deposit = 2 };
    Kind kind = Regular;
    Hash32 txid; // Txid / CoinbaseTxid / bitcoin Txid (internal byte order)
    uint32_t vout = 0;
    friend auto operator<=>(const OutPoint&, const OutPoint&) = default;
    friend bool operator==(const OutPoint&, const OutPoint&) = default;
    /** 37-byte borsh form (OutPointKey), also the key of utxos/stxos. */
    std::array<uint8_t, 37> key() const;
    static OutPoint from_key(ByteSpan k);
    std::string to_string() const;
};

struct InPoint {
    enum Kind : uint8_t { Regular = 0, Withdrawal = 1 };
    Kind kind = Regular;
    Hash32 id; // txid, or m6id (internal byte order)
    uint32_t vin = 0;
    bool operator==(const InPoint&) const = default;
};

struct SpentOutput {
    FilledOutput output;
    InPoint inpoint;
    bool operator==(const SpentOutput&) const = default;
};

struct Transaction {
    std::vector<OutPoint> inputs;
    std::vector<Output> outputs;
    Bytes memo;
    std::optional<TxData> data;

    Bytes canonical_bytes() const; // borsh
    uint64_t canonical_size() const { return canonical_bytes().size(); }
    Hash32 txid() const;
    bool is_reservation() const { return data && data->kind == TxData::Reservation; }
    bool is_registration() const { return data && data->kind == TxData::Registration; }
    bool is_update() const { return data && data->kind == TxData::Update; }
    bool is_batch_icann() const { return data && data->kind == TxData::BatchIcann; }
    /** blake3::keyed_hash(revealed_nonce, name_hash) for registrations. */
    std::optional<Hash32> implied_reservation_commitment() const;
};

struct Authorization {
    bt::frost::Point verifying_key;
    bt::frost::Signature signature;
};

struct AuthorizedTransaction {
    Transaction transaction;
    std::vector<Authorization> authorizations;
};

struct Coinbase {
    Bytes memo;
    std::vector<Output> outputs;
};

struct Body {
    Coinbase coinbase;
    std::vector<Transaction> transactions;
    std::vector<Authorization> authorizations;
    size_t inputs_len() const;
    /** Body::authorized_transactions: authorizations dealt out by input count. */
    std::vector<AuthorizedTransaction> authorized_transactions() const;
    static Body from_authorized(std::vector<AuthorizedTransaction> txs, Coinbase cb);
    static constexpr size_t MAX_SIZE = 8 * 1024 * 1024;
};

/** types/lib.rs:76-101 */
struct Header {
    Hash32 merkle_root;
    std::optional<Hash32> prev_side_hash;
    Hash32 prev_main_hash; // bitcoin block hash, internal byte order

    Hash32 hash() const;
    Hash32 coinbase_txid() const;
    bool operator==(const Header&) const = default;
};

struct Block {
    Header header;
    Body body;
};

/** A transaction together with the outputs it spends (FilledTransaction). */
struct FilledTransaction {
    const Transaction* tx = nullptr;
    std::vector<FilledOutput> spent_utxos;
    /** get_fee / fee(): checked sums, error (nullopt) on overflow or underfunding. */
    std::optional<uint64_t> fee() const;
    /** filled_outputs (transaction/mod.rs:873-901); nullopt if the tokens run out. */
    std::optional<std::vector<FilledOutput>> filled_outputs() const;
    /** spent_utxos_requiring_auth: all spent outputs, minus the BitName inputs a BatchIcann
     *  consumes (in plain-name order). */
    std::vector<FilledOutput> spent_utxos_requiring_auth() const;
};

// ---------------------------------------------------------------- borsh
void borsh(Writer& w, const Address& a);
void borsh(Writer& w, const Content& c);
void borsh(Writer& w, const Output& o);
void borsh(Writer& w, const OutPoint& o);
void borsh(Writer& w, const MutableBitNameData& d);
void borsh(Writer& w, const BitNameDataUpdates& u);
void borsh(Writer& w, const TxData& d);
void borsh(Writer& w, const Transaction& t);
void borsh(Writer& w, const Authorization& a);
void borsh(Writer& w, const Coinbase& c);
void borsh(Writer& w, const Body& b);
void borsh(Writer& w, const Header& h);
template <class T>
Bytes borsh_bytes(const T& x)
{
    Writer w;
    borsh(w, x);
    return w.buf;
}
template <class T>
Hash32 hash(const T& x)
{
    return bt::blake3(borsh_bytes(x));
}

/** borsh decoders (the seed index serves txs as borsh hex; our wallet tests). */
Transaction borsh_de_transaction(Reader& r);

// ---------------------------------------------------------------- bincode (serde)
void bincode(Writer& w, const Content& c);
void bincode(Writer& w, const Output& o);
void bincode(Writer& w, const OutPoint& o);
void bincode(Writer& w, const MutableBitNameData& d);
void bincode(Writer& w, const BitNameDataUpdates& u);
void bincode(Writer& w, const TxData& d);
void bincode(Writer& w, const Transaction& t);
void bincode(Writer& w, const Authorization& a);
void bincode(Writer& w, const AuthorizedTransaction& t);
void bincode(Writer& w, const Coinbase& c);
void bincode(Writer& w, const Body& b);
void bincode(Writer& w, const Header& h);
void bincode(Writer& w, const FilledContent& c);
void bincode(Writer& w, const FilledOutput& o);

Content de_content(Reader& r);
Output de_output(Reader& r);
OutPoint de_outpoint(Reader& r);
MutableBitNameData de_bitname_data(Reader& r);
TxData de_txdata(Reader& r);
Transaction de_transaction(Reader& r);
Authorization de_authorization(Reader& r);
AuthorizedTransaction de_authorized_transaction(Reader& r);
Coinbase de_coinbase(Reader& r);
Body de_body(Reader& r);
Header de_header(Reader& r);
FilledContent de_filled_content(Reader& r);
FilledOutput de_filled_output(Reader& r);

// ---------------------------------------------------------------- merkle (types/lib.rs:448-850)
/** Body::compute_merkle_root: nullopt where theirs errs or panics (block invalid).
 *  Transactions: fee/size CBMT below 1000 txs, a duplicate-last levelized tree from 1000. */
std::optional<Hash32> compute_merkle_root(const Coinbase& cb, const std::vector<FilledTransaction>& txs);
/** Coinbase::compute_merkle_root = blake3(borsh((memo, outputs_cbmt_root))). */
std::optional<Hash32> coinbase_merkle_root(const Coinbase& cb);
/** Coinbase::compute_txid = blake3(borsh{merkle_root, prev_main_hash, prev_side_hash}). */
Hash32 compute_coinbase_txid(const Hash32& merkle_root, const Hash32& prev_main_hash, const std::optional<Hash32>& prev_side);
constexpr size_t MERKLE_LEVELIZED_FROM = 1000;

// ---------------------------------------------------------------- authorizations (types/authorization.rs)
/** Dst::Transaction (0) prefixed message the signatures cover. */
Bytes tx_signing_message(const Transaction& t);
/** verify_authorized_transaction: exact count; zero inputs pass without signatures. */
bool verify_authorized_transaction(const AuthorizedTransaction& tx);
/** verify_authorizations: exact count Σinputs, every signature over its tx message. */
bool verify_authorizations(const Body& body);
/** authorization::verify with a domain tag (0 = Transaction, 255 = Arbitrary). */
bool verify_with_dst(const bt::frost::Signature& sig, const bt::frost::Point& vk, uint8_t dst, ByteSpan msg);
bt::frost::Signature sign_with_dst(const bt::frost::SigningKey& sk, uint8_t dst, ByteSpan msg);

/** BitNameSeqId Display/FromStr ("1739-0029" style, offset 23071990). */
std::string seq_id_to_string(uint32_t seq);
std::optional<uint32_t> seq_id_from_string(std::string_view s);

/** blake3(plain name), the BitName id wallets use. */
Hash32 name_hash(std::string_view plain);

} // namespace bitnames
