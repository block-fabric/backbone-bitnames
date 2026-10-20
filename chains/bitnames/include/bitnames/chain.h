// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// BitNames' traits for the core's archive and P2P templates, and its network constants
// (fork lib/net/peer/message.rs:19-37, lib/net/mod.rs:169-195, types/net.rs).
#pragma once

#include <bitnames/types.h>

#include <bt/sidechain/archive.h>
#include <bt/sidechain/p2p.h>

namespace bitnames {

struct Chain {
    using Header = bitnames::Header;
    using Body = bitnames::Body;
    using AuthorizedTransaction = bitnames::AuthorizedTransaction;
    static constexpr size_t MIN_HEADER_BYTES = 32 + 1 + 8 + 32;
    static Hash32 hash(const Header& h) { return h.hash(); }
    static void encode_header(Writer& w, const Header& h) { bincode(w, h); }
    static Header decode_header(Reader& r) { return de_header(r); }
    static void encode_body(Writer& w, const Body& b) { bincode(w, b); }
    static Body decode_body(Reader& r) { return de_body(r); }
    static void encode_authorized_tx(Writer& w, const AuthorizedTransaction& t) { bincode(w, t); }
    static AuthorizedTransaction decode_authorized_tx(Reader& r) { return de_authorized_transaction(r); }
    static std::vector<Hash32> txids(const Body& b)
    {
        std::vector<Hash32> r;
        for (auto& t : b.transactions) r.push_back(t.txid());
        return r;
    }
};

using Archive = bt::sidechain::Archive<Chain>;
using P2P = bt::sidechain::P2P<Chain>;
using bt::sidechain::BmmResult;
using bt::sidechain::Network;
using bt::sidechain::TipRef;
using bt::sidechain::U256;

/** "BTNMS" Baudot prefix; Betanet = cc19c284, Regtest 80, Signet 81, Forknet 82. */
inline std::array<uint8_t, 4> magic_bytes(Network n) { return bt::sidechain::magic_bytes({0xcc, 0x19, 0xc2, 0x80}, n); }
constexpr uint16_t DEFAULT_PORT = 4000 + THIS_SIDECHAIN;     // P2P
constexpr uint16_t DEFAULT_RPC_PORT = 6000 + THIS_SIDECHAIN; // JSON-RPC
constexpr uint16_t DEFAULT_ZMQ_PORT = 28000 + THIS_SIDECHAIN;
/** fork lib/net/mod.rs: seed peers per network. */
std::vector<std::string> seed_peers(Network n);
inline const char* VERSION = "0.18.2";

} // namespace bitnames
