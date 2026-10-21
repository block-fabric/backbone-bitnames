// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// JSON forms of BitNames types exactly as serde_json renders them in the fork's JSON-RPC
// (human-readable serde): hex hashes and memos, base58 addresses, Bech32m keys, display-order
// bitcoin hashes, externally tagged enums, [u8; 32] commitments as number arrays where the
// type has no hex adapter, "1739-0029" seq ids.
#pragma once

#include <bitnames/state.h>

#include <bt/jsonrpc.h>
#include <univalue.h>

namespace bitnames::json {

UniValue hash(const Hash32& h);     // hex (BlockHash, Txid, MerkleRoot, BitName, ...)
UniValue btc_hash(const Hash32& h); // display order (bitcoin::BlockHash, Txid, M6id)
UniValue bytes_array(ByteSpan b);   // serde of [u8; N]: array of numbers
UniValue address(const Address& a);
UniValue outpoint(const OutPoint& o);
UniValue content(const Content& c);
UniValue filled_content(const FilledContent& c);
UniValue output(const Output& o);
UniValue filled_output(const FilledOutput& o);
UniValue spent_output(const SpentOutput& s);
UniValue inpoint(const InPoint& i);
UniValue pointed(const OutPoint& op, const UniValue& output);
UniValue mutable_data(const MutableBitNameData& d);
UniValue bitname_data(const BitNameData& d); // {seq_id, ...flattened}
UniValue updates(const BitNameDataUpdates& u);
UniValue txdata(const TxData& d);
UniValue transaction(const Transaction& t);
UniValue signature(const bt::frost::Signature& s);
UniValue authorization(const Authorization& a);
UniValue authorized_transaction(const AuthorizedTransaction& t);
UniValue coinbase(const Coinbase& c);
UniValue body(const Body& b);
UniValue header(const Header& h);
UniValue block(const Header& h, const Body& b, uint32_t height);
UniValue bitcoin_tx(const std::vector<bt::btc::TxOut>& outs);
UniValue withdrawal_bundle(const WithdrawalBundle& w);

/** A request value that does not parse: jsonrpsee's -32602 "Invalid params", the cause (serde's) as data;
 *  `at`: the value it is about (the server adds serde_json's position of it). */
struct Error : bt::jsonrpc::RpcError {
    explicit Error(const std::string& cause, const UniValue* at = nullptr) : bt::jsonrpc::RpcError(-32602, "Invalid params", cause, at) {}
};
/** serde's Unexpected of a JSON value ("string \"x\"", "integer `5`", "sequence", ...). */
std::string serde_unexpected(const UniValue& v);
/** serde's derived Deserialize of a struct: an object with the (non-Option) `fields`, else serde's error. */
void require_struct(const UniValue& v, const char* name, std::initializer_list<const char*> fields);
Hash32 parse_hash(const UniValue& v);
Hash32 parse_btc_hash(const UniValue& v);
Address parse_address(const UniValue& v);
bt::btc::Address parse_btc_address(const UniValue& v);
OutPoint parse_outpoint(const UniValue& v);
Output parse_output(const UniValue& v);
MutableBitNameData parse_mutable_data(const UniValue& v);
TxData parse_txdata(const UniValue& v);
Transaction parse_transaction(const UniValue& v);
bt::frost::Signature parse_signature(const UniValue& v);
bt::frost::Point parse_vk(const UniValue& v);
bt::ByteArray<32> parse_epk(const UniValue& v);
AuthorizedTransaction parse_authorized_transaction(const UniValue& v);
Header parse_header(const UniValue& v);
Body parse_body(const UniValue& v);
uint64_t parse_u64(const UniValue& v);
uint32_t parse_u32(const UniValue& v);
Bytes parse_hex(const UniValue& v);

} // namespace bitnames::json
