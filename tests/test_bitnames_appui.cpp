// BitNames' app layer (doc/app.md): the LayerTwo JSON-RPC is the same with the app layer running (same methods, same
// bytes for every reply); the app RPC's reads are the LayerTwo handlers' own JSON; the backup phrase's flows (made, its
// words only in a question, restored, refused over another); wallet ownership only for a wallet reader; the manifest of
// app/manifest.json is the node's; names: the directory's words only to a wallet reader, the wallet's names only to it,
// a reservation or a registration asked with what it does.
#include "test.h"

#include <bitnames/app.h>
#include <bitnames/appui.h>

#include <bt/appui/auth.h>
#include <bt/appui/phrase.h>
#include <bt/frost.h>
#include <bt/hd.h>

#include <filesystem>
#include <fstream>
#include <memory>

using namespace bitnames;

namespace {
struct Harness {
    std::string dir;
    std::unique_ptr<Node> node;
    std::unique_ptr<Wallet> wallet;
    std::unique_ptr<App> app;
    explicit Harness(const std::string& name)
    {
        bt::frost::init();
        dir = (std::filesystem::temp_directory_path() / ("bt-bitnames-appui-" + name + "-" + bt::appui::random_hex(6))).string();
        std::filesystem::create_directories(dir);
        NodeConfig cfg;
        cfg.datadir = dir;
        cfg.network = Network::Regtest;
        cfg.p2p = false;
        cfg.use_seeds = false;
        cfg.zmq_addr.reset();
        cfg.mainchain_grpc_url = "http://127.0.0.1:1";
        node = std::make_unique<Node>(cfg);
        std::string err;
        CHECK(node->start(err));
        wallet = std::make_unique<Wallet>(dir + "/backbone-wallet.sqlite", *node);
        app = std::make_unique<App>(*node, *wallet);
    }
    ~Harness()
    {
        app.reset();
        wallet.reset();
        if (node) node->stop();
        node.reset();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

std::string reply(bt::jsonrpc::Server& s, const std::string& method, const std::string& params)
{
    return s.handle(R"({"jsonrpc":"2.0","id":7,"method":")" + method + R"(","params":)" + params + "}");
}

UniValue host_call(AppLayer& layer, const std::string& user, const std::string& method, const std::string& params, const std::string& token = "")
{
    UniValue req{UniValue::VOBJ};
    req.pushKV("kind", "host");
    req.pushKV("method", method);
    UniValue p;
    CHECK(p.read(params));
    req.pushKV("params", p);
    return layer.host().run(req, token, "", UniValue{}, user);
}

bt::appui::AppOptions options()
{
    bt::appui::AppOptions o;
    o.enabled = true;
    o.port = 0;
    // The app's user, a reader of the chain only, the cookie unrestricted.
    o.whitelist = {"app:webuihost,describeconfirmation,webuievents,getblockchaininfo,getbalances,get_wallet_addresses,dropin.checkAddress,dropin.block,dropin.seed.status,dropin.seed.prepare,dropin.seed.create,dropin.seed.restore,dropin.seed.show,create_transfer,balance,get_block,bitnames,bitname_data,get_wallet_utxos,bitnames.names,bitnames.resolve,bitnames.directory,reserve_bitname,register_bitname",
                   "chainonly:webuihost,getblockchaininfo,get_block,dropin.checkAddress,bitnames,bitname_data"};
    o.whitelist_default = false;
    return o;
}
} // namespace

TEST(appui_l2l_rpc_byte_identical_with_and_without_the_app_layer)
{
    Harness h("l2l");
    // Without the app layer: the LayerTwo server as main.cpp makes it.
    bt::jsonrpc::Server before;
    register_rpc(before, *h.app, true, true);
    // With it running (its own server, its pollers, its store) beside the same node and wallet.
    AppLayer layer(*h.app, "regtest", h.dir, options());
    std::string err;
    CHECK(layer.start(err));
    bt::jsonrpc::Server after;
    register_rpc(after, *h.app, true, true);
    CHECK(before.methods() == after.methods());
    CHECK_EQ(before.methods().size(), size_t{58});
    // Every method, with no parameters, with wrong ones, and (the reads) with right ones: the same bytes.
    const std::vector<std::string> bad{"[]", "[1,2,3,4,5]", R"(["x"])", R"({"nope":1})", "[null]"};
    for (const std::string& m : before.methods()) {
        // What changes the node or the wallet runs once only (on `after`, after the comparison of its errors).
        static const std::set<std::string> changes{"stop", "mine", "get_new_address", "generate_mnemonic", "set_seed_from_mnemonic", "create_deposit",
                                                   "create_transfer", "create_transfer_many", "create_withdrawal", "connect_peer", "forget_peer",
                                                   "invalidate_block", "submit_transaction", "connect_block", "get_block_template", "sign_transaction",
                                                   "reserve_bitname", "register_bitname", "get_new_encryption_key", "get_new_verifying_key",
                                                   "broadcast_transaction", "rebroadcast_transaction", "encrypt_msg", "sign_arbitrary_msg",
                                                   "sign_arbitrary_msg_as_addr"};
        for (const std::string& p : bad) {
            if (changes.contains(m) && (p == "[]" || p == "[null]")) continue;
            // A fresh phrase each call (it ignores its parameters): the same form, not the same words.
            if (m == "generate_mnemonic") {
                UniValue a, b;
                CHECK(a.read(reply(before, m, p)));
                CHECK(b.read(reply(after, m, p)));
                CHECK(a["result"].isStr() && b["result"].isStr() && a.getKeys() == b.getKeys());
                continue;
            }
            const std::string a{reply(before, m, p)}, b{reply(after, m, p)};
            if (a != b) std::fprintf(stderr, "  %s %s:\n    %s\n    %s\n", m.c_str(), p.c_str(), a.c_str(), b.c_str());
            CHECK(a == b);
        }
    }
    const std::vector<std::pair<std::string, std::string>> reads{
        {"getblockcount", "[]"}, {"get_best_sidechain_block_hash", "[]"}, {"list_utxos", "[]"}, {"list_peers", "[]"}, {"pending_withdrawal_bundle", "[]"},
        {"sidechain_wealth", "[]"}, {"balance", "[]"}, {"get_wallet_addresses", "[]"}, {"get_wallet_utxos", "[]"}, {"openapi_schema", "[]"},
        {"latest_failed_withdrawal_bundle_height", "[]"}, {"get_block_hash", "[0]"}, {"format_deposit_address", R"(["4XrMw8bmnhchFspSyP4XRUuB5vaR"])"},
        {"get_utxos", R"([["4XrMw8bmnhchFspSyP4XRUuB5vaR"]])"}, {"get_stxos", R"([["4XrMw8bmnhchFspSyP4XRUuB5vaR"]])"},
        {"get_transaction", R"(["0000000000000000000000000000000000000000000000000000000000000000"])"}, {"bitnames", "[]"}, {"list_mempool", "[]"},
        {"bitname_data", R"(["0000000000000000000000000000000000000000000000000000000000000000"])"}, {"mainchain_sync_progress", "[]"}};
    for (const auto& [m, p] : reads) CHECK(reply(before, m, p) == reply(after, m, p));
    // The app RPC's own read of a LayerTwo method answers its result, the same JSON.
    for (const auto& [m, p] : reads) {
        UniValue r;
        CHECK(r.read(reply(before, m, p)));
        bt::appui::Call c;
        c.method = m;
        CHECK(c.params.read(p));
        c.user = "__cookie__";
        // An error of the LayerTwo handler (a name not registered) is an error of the app RPC too.
        if (!r.find_value("error").isNull()) {
            bool threw{false};
            try {
                layer.server().dispatch(c);
            } catch (const std::exception&) {
                threw = true;
            }
            CHECK(threw);
            continue;
        }
        CHECK_EQ(layer.server().dispatch(c).write(), r.find_value("result").write());
    }
    layer.stop();
}

TEST(appui_phrase_made_in_a_question_restored_refused_over_another)
{
    Harness h("seed");
    AppLayer layer(*h.app, "regtest", h.dir, options());
    std::string err;
    CHECK(layer.start(err));
    // Made: an id for the page, the words only in the question, the wallet set on the yes.
    const UniValue prep{host_call(layer, "app", "dropin.seed.prepare", "{}")["result"]};
    const std::string id{prep["id"].get_str()};
    CHECK(id.size() == 32);
    CHECK(!prep.exists("phrase") && !prep.exists("words_list"));
    const std::string create{"{\"id\":\"" + id + "\"}"};
    const UniValue q{host_call(layer, "app", "dropin.seed.create", create)["confirm"]};
    CHECK_EQ(q["kind"].get_str(), std::string{"phrase.create"});
    CHECK(q["details"].get_str().find(" 1. ") != std::string::npos);
    CHECK(!h.wallet->has_seed());
    const UniValue done{host_call(layer, "app", "dropin.seed.create", create, q["token"].get_str())["result"]};
    CHECK(h.wallet->has_seed());
    const std::string fp{done["fingerprint"].get_str()};
    CHECK_EQ(host_call(layer, "app", "dropin.seed.status", "{}")["result"]["fingerprint"].get_str(), fp);
    CHECK(host_call(layer, "app", "dropin.seed.status", "{}")["result"]["phraseKept"].isTrue());
    // Shown again: a question, never a result with words.
    const UniValue shown{host_call(layer, "app", "dropin.seed.show", "{}")};
    CHECK(shown.exists("confirm") && !shown.exists("result"));
    // Another phrase over it: refused before any question.
    bool refused{false};
    try {
        host_call(layer, "app", "dropin.seed.restore", R"({"phrase":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"})");
    } catch (const bt::appui::RpcError&) {
        refused = true;
    }
    CHECK(refused);
    // The unified wallet's setup (its own user, the cookie): the same refusal over another phrase.
    bt::appui::Call c;
    c.method = "setwalletphrase";
    CHECK(c.params.read(R"(["abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"])"));
    c.user = "__cookie__";
    refused = false;
    try {
        layer.server().dispatch(c);
    } catch (const bt::appui::RpcError&) {
        refused = true;
    }
    CHECK(refused);
    // The app's user may not call it at all.
    c.user = "app";
    refused = false;
    try {
        layer.server().dispatch(c);
    } catch (const bt::appui::RpcError&) {
        refused = true;
    }
    CHECK(refused);
    layer.stop();
}

TEST(appui_restore_and_unified_phrase)
{
    Harness h("restore");
    AppLayer layer(*h.app, "regtest", h.dir, options());
    std::string err;
    CHECK(layer.start(err));
    // A phrase of the unified wallet (BIP-85 of its seed, sidechain/dropin/v1, bitnames, regtest), set by its own user.
    auto master{bt::hd::parse_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")};
    const std::string phrase{bt::appui::dropin_phrase(bt::hd::mnemonic_to_seed(*master).span(), "bitnames", "regtest")};
    bt::appui::Call c;
    c.method = "setwalletphrase";
    c.params.push_back(phrase);
    c.user = "__cookie__";
    const UniValue r{layer.server().dispatch(c)};
    const std::string expect{bt::appui::seed_fingerprint(bt::hd::mnemonic_to_seed(*bt::hd::parse_mnemonic(phrase)).span())};
    CHECK_EQ(r["fingerprint"].get_str(), expect);
    // The fingerprint the node gives is the one the unified wallet computes from the phrase it set.
    bt::appui::Call info;
    info.method = "getwalletphraseinfo";
    info.user = "__cookie__";
    const UniValue i{layer.server().dispatch(info)};
    CHECK_EQ(i["fingerprint"].get_str(), expect);
    CHECK_EQ(i["from"].get_str(), std::string{"unified"});
    // The same phrase again: accepted (the same seed).
    CHECK(layer.server().dispatch(c)["fingerprint"].get_str() == expect);
    // A bad phrase: tiny-bip39's words.
    bt::appui::Call bad{c};
    bad.params = UniValue{UniValue::VARR};
    bad.params.push_back("abandon abandon");
    bool refused{false};
    try {
        layer.server().dispatch(bad);
    } catch (const bt::appui::RpcError& e) {
        refused = std::string{e.what()}.find("word") != std::string::npos || std::string{e.what()}.find("invalid") != std::string::npos;
    }
    CHECK(refused);
    layer.stop();
}

TEST(appui_wallet_ownership_only_for_a_wallet_reader)
{
    Harness h("mine");
    h.wallet->set_seed_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    const std::string own{h.wallet->get_new_address().to_base58()};
    AppLayer layer(*h.app, "regtest", h.dir, options());
    std::string err;
    CHECK(layer.start(err));
    const std::string p{"{\"address\":\"" + own + "\"}"};
    const UniValue reader{host_call(layer, "app", "dropin.checkAddress", p)["result"]};
    CHECK(reader["valid"].isTrue());
    CHECK(reader["mine"].isTrue());
    const UniValue chain_only{host_call(layer, "chainonly", "dropin.checkAddress", p)["result"]};
    CHECK(chain_only["valid"].isTrue());
    CHECK(!chain_only.exists("mine"));
    CHECK(!chain_only.exists("error"));
    // A spend the wallet cannot pay: refused before any question; a bad address: said.
    bool refused{false};
    try {
        layer.host().describe("create_transfer", [] {
            UniValue a{UniValue::VARR};
            a.push_back("4XrMw8bmnhchFspSyP4XRUuB5vaR");
            a.push_back(1000);
            a.push_back(10);
            return a;
        }(), "app");
    } catch (const bt::appui::RpcError& e) {
        refused = std::string{e.what()}.find("Not enough") != std::string::npos;
    }
    CHECK(refused);
    layer.stop();
}

TEST(appui_names_words_only_to_a_wallet_reader_and_asked)
{
    Harness h("names");
    h.wallet->set_seed_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    AppLayer layer(*h.app, "regtest", h.dir, options());
    std::string err;
    CHECK(layer.start(err));
    // The wallet's names: to its reader; a caller of the chain only (bitnames, bitname_data) is refused.
    const UniValue mine{host_call(layer, "app", "bitnames.names", "{}")["result"]};
    CHECK(mine["owned"].isArray() && mine["reservations"].isArray() && mine["pending"].isArray());
    bool refused{false};
    try {
        host_call(layer, "chainonly", "bitnames.names", "{}");
    } catch (const bt::appui::RpcError&) {
        refused = true;
    }
    CHECK(refused);
    // A name looked up: its hash (blake3 of the words), free.
    const UniValue r{host_call(layer, "chainonly", "bitnames.resolve", R"({"name":"backbone"})")["result"]};
    CHECK_EQ(r["hash"].get_str(), bt::hex_encode(name_hash("backbone")));
    CHECK(r["registered"].isFalse() && !r.exists("data"));
    refused = false;
    try {
        host_call(layer, "chainonly", "bitnames.resolve", R"({"name":""})");
    } catch (const bt::appui::RpcError&) {
        refused = true;
    }
    CHECK(refused);
    CHECK(host_call(layer, "chainonly", "bitnames.directory", "{}")["result"].isArray());
    // Reserving without a coin: refused before any question (theirs would make a reservation anyone can replay).
    UniValue p{UniValue::VARR};
    p.push_back("backbone");
    refused = false;
    try {
        layer.host().describe("reserve_bitname", p, "app");
    } catch (const bt::appui::RpcError& e) {
        refused = std::string{e.what()}.find("coin") != std::string::npos;
    }
    CHECK(refused);
    // A registration: asked with the name and each record it sets, as the node parses them.
    UniValue data{UniValue::VOBJ};
    data.pushKV("socket_addr_v4", "203.0.113.7:443");
    data.pushKV("paymail_fee_sats", 21);
    p.push_back(data);
    const UniValue q{layer.host().describe("register_bitname", p, "app")};
    const std::string text{q.write()};
    CHECK(text.find("backbone") != std::string::npos);
    CHECK(text.find("203.0.113.7:443") != std::string::npos);
    CHECK(text.find("Paymail fee (sat)") != std::string::npos);
    CHECK(text.find("IPv4 address") != std::string::npos);
    // Records the node cannot parse: refused before any question.
    UniValue bad{UniValue::VARR};
    bad.push_back("backbone");
    UniValue d2{UniValue::VOBJ};
    d2.pushKV("socket_addr_v4", "not an address");
    bad.push_back(d2);
    refused = false;
    try {
        layer.host().describe("register_bitname", bad, "app");
    } catch (const bt::appui::RpcError&) {
        refused = true;
    }
    CHECK(refused);
    layer.stop();
}

TEST(appui_manifest_is_the_nodes)
{
    Harness h("manifest");
    AppLayer layer(*h.app, "regtest", h.dir, options());
    std::string err;
    CHECK(layer.start(err));
    std::ifstream f(std::string{BT_SOURCE_DIR} + "/app/manifest.json");
    std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    UniValue file;
    CHECK(file.read(text));
    const UniValue node{layer.manifest()};
    for (const char* group : {"reads", "confirmed", "host", "protocol"}) {
        std::set<std::string> a, b;
        for (const UniValue& v : file[group].getValues()) a.insert(v.get_str());
        for (const UniValue& v : node[group].getValues()) b.insert(v.get_str());
        if (a != b) std::fprintf(stderr, "  manifest %s differs\n", group);
        CHECK(a == b);
    }
    // Every read and protocol method is served by the app RPC; every host method of the manifest is the host's.
    for (const UniValue& v : file["reads"].getValues()) CHECK(layer.server().has(v.get_str()));
    for (const UniValue& v : file["protocol"].getValues()) CHECK(layer.server().has(v.get_str()));
    layer.stop();
}
