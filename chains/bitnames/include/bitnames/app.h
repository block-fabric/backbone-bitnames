// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// BitNames application: node + wallet, block templates, BMM mining, deposits, paymail
// (fork app/app.rs) and the JSON-RPC surface (rpc-api/lib.rs, app/rpc_server.rs): the 58
// methods their node serves, with serde_json shapes.
#pragma once

#include <bitnames/node.h>
#include <bitnames/wallet.h>

#include <bt/jsonrpc.h>

namespace bitnames {

struct BlockTemplate {
    uint64_t bribe = 0;
    Header header;
    uint32_t height = 0;
    Body body;
    uint64_t fees = 0;
};

class App {
public:
    App(Node& node, Wallet& wallet) : node(node), wallet(wallet) {}
    Node& node;
    Wallet& wallet;

    static constexpr uint64_t EMPTY_BLOCK_BMM_BRIBE = 1000; // app.rs:567
    BlockTemplate build_block_template(std::optional<uint64_t> fee);
    void mine(std::optional<uint64_t> fee);
    bool connect_block(const Header& h, const Body& b, const Hash32& main_block_hash);
    Hash32 deposit(const Address& a, uint64_t value, uint64_t fee);
    /** app.rs get_paymail: memo-carrying wallet UTXOs paying at least the paymail fee of a
     *  BitName the receiving address owned when the output was created. */
    std::map<OutPoint, FilledOutput> get_paymail();
    std::function<void()> on_stop;
};

/** Register the RPC methods (rpc_server.rs run_server): the public server gets the node
 *  API, the private one the private node API and the wallet; one server gets all. */
void register_rpc(bt::jsonrpc::Server& s, App& app, bool public_api, bool private_api);

} // namespace bitnames
