// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// `bitnames-cli`: the subcommands and output of the plain-bitnames fork's
// plain_bitnames_app_cli (cli/lib.rs, shipped as `bitnames-cli`) over the node's JSON-RPC.
// JSON results print like serde_json::to_string_pretty; scalars like Rust's Display.
#include <bitnames/chain.h>

#include <bt/crypto.h>
#include <bt/jsonrpc.h>
#include <bt/parse.h>

#include <algorithm>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

namespace {

enum class Out { Pretty, Display, Empty };

struct Spec {
    std::string rpc;
    std::vector<std::string> positional;                    // positional CLI args, in order
    std::vector<std::pair<std::string, std::string>> flags; // --flag -> rpc param name
    Out out = Out::Pretty;
    std::vector<std::string> json_args; // args/flags whose value is JSON (numbers, objects)
};

std::map<std::string, Spec> specs()
{
    std::map<std::string, Spec> m;
    auto add = [&](const std::string& cmd, Spec s) { m[cmd] = std::move(s); };
    add("balance", {"balance", {}, {}, Out::Pretty, {}});
    add("bitname-data", {"bitname_data", {"bitname_id"}, {}, Out::Pretty, {}});
    add("bitnames", {"bitnames", {}, {}, Out::Pretty, {}});
    add("connect-block", {"connect_block", {"block", "main_block_hash"}, {}, Out::Display, {"block"}});
    add("connect-peer", {"connect_peer", {"addr"}, {}, Out::Empty, {}});
    add("create-deposit", {"create_deposit", {"address"}, {{"--value-sats", "value_sats"}, {"--fee-sats", "fee_sats"}}, Out::Display, {"value_sats", "fee_sats"}});
    add("create-transfer", {"create_transfer", {"dest"}, {{"--value-sats", "value_sats"}, {"--fee-sats", "fee_sats"}}, Out::Display, {"value_sats", "fee_sats"}});
    add("create-transfer-many", {"create_transfer_many", {"dests"}, {{"--fee-sats", "fee_sats"}}, Out::Display, {"dests", "fee_sats"}});
    add("create-withdrawal", {"create_withdrawal", {"mainchain_address"},
                              {{"--amount-sats", "amount_sats"}, {"--fee-sats", "fee_sats"}, {"--mainchain-fee-sats", "mainchain_fee_sats"}},
                              Out::Display, {"amount_sats", "fee_sats", "mainchain_fee_sats"}});
    add("decrypt-msg", {"decrypt_msg", {}, {{"--encryption-pubkey", "encryption_pubkey"}, {"--msg", "ciphertext"}}, Out::Display, {}});
    add("encrypt-msg", {"encrypt_msg", {}, {{"--encryption-pubkey", "encryption_pubkey"}, {"--msg", "msg"}}, Out::Display, {}});
    add("forget-peer", {"forget_peer", {"addr"}, {}, Out::Empty, {}});
    add("format-deposit-address", {"format_deposit_address", {"address"}, {}, Out::Display, {}});
    add("generate-mnemonic", {"generate_mnemonic", {}, {}, Out::Display, {}});
    add("get-best-mainchain-block-hash", {"get_best_mainchain_block_hash", {}, {}, Out::Pretty, {}});
    add("get-best-sidechain-block-hash", {"get_best_sidechain_block_hash", {}, {}, Out::Pretty, {}});
    add("get-block", {"get_block", {"block_hash"}, {}, Out::Pretty, {}});
    add("get-blockcount", {"getblockcount", {}, {}, Out::Display, {}});
    add("get-block-hash", {"get_block_hash", {"height"}, {}, Out::Pretty, {"height"}});
    add("get-block-index", {"get_block_index", {"block_hash"}, {}, Out::Pretty, {}});
    add("get-block-template", {"get_block_template", {}, {}, Out::Pretty, {}});
    add("get-bmm-inclusions", {"get_bmm_inclusions", {"block_hash"}, {}, Out::Pretty, {}});
    add("get-new-address", {"get_new_address", {}, {}, Out::Display, {}});
    add("get-new-encryption-key", {"get_new_encryption_key", {}, {}, Out::Display, {}});
    add("get-new-verifying-key", {"get_new_verifying_key", {}, {}, Out::Display, {}});
    add("get-paymail", {"get_paymail", {}, {}, Out::Pretty, {}});
    add("get-wallet-addresses", {"get_wallet_addresses", {}, {}, Out::Pretty, {}});
    add("get-wallet-master-xesk", {"get_wallet_master_xesk", {}, {}, Out::Display, {}});
    add("get-wallet-master-xvk", {"get_wallet_master_xvk", {}, {}, Out::Display, {}});
    add("get-wallet-utxos", {"get_wallet_utxos", {}, {}, Out::Pretty, {}});
    add("invalidate-block", {"invalidate_block", {"block_hash"}, {}, Out::Empty, {}});
    add("latest-failed-withdrawal-bundle-height", {"latest_failed_withdrawal_bundle_height", {}, {}, Out::Pretty, {}});
    add("list-mempool", {"list_mempool", {}, {}, Out::Pretty, {}});
    add("list-peers", {"list_peers", {}, {}, Out::Pretty, {}});
    add("list-stxos", {"list_stxos", {}, {}, Out::Pretty, {}});
    add("list-utxos", {"list_utxos", {}, {}, Out::Pretty, {}});
    add("mainchain-sync-progress", {"mainchain_sync_progress", {}, {}, Out::Pretty, {}});
    add("mine", {"mine", {}, {{"--fee-sats", "fee"}}, Out::Empty, {"fee"}});
    add("my-utxos", {"my_utxos", {}, {}, Out::Pretty, {}});
    add("openapi-schema", {"openapi_schema", {}, {}, Out::Pretty, {}});
    add("pending-withdrawal-bundle", {"pending_withdrawal_bundle", {}, {}, Out::Pretty, {}});
    add("reserve-bitname", {"reserve_bitname", {"plain_name"}, {}, Out::Display, {}});
    add("set-seed-from-mnemonic", {"set_seed_from_mnemonic", {"mnemonic"}, {}, Out::Empty, {}});
    add("sidechain-wealth", {"sidechain_wealth", {}, {}, Out::Display, {}});
    add("sign-arbitrary-msg", {"sign_arbitrary_msg", {}, {{"--verifying-key", "verifying_key"}, {"--msg", "msg"}}, Out::Display, {}});
    add("sign-arbitrary-msg-as-addr", {"sign_arbitrary_msg_as_addr", {}, {{"--address", "address"}, {"--msg", "msg"}}, Out::Pretty, {}});
    add("sign-transaction", {"sign_transaction", {"transaction", "broadcast"}, {}, Out::Pretty, {"transaction", "broadcast"}});
    add("submit-transaction", {"submit_transaction", {"transaction"}, {}, Out::Display, {"transaction"}});
    add("stop", {"stop", {}, {}, Out::Empty, {}});
    add("verify-signature", {"verify_signature", {},
                             {{"--signature", "signature"}, {"--verifying-key", "verifying_key"}, {"--dst", "dst"}, {"--msg", "msg"}},
                             Out::Display, {}});
    return m;
}

void json_str(std::string& o, const std::string& s)
{
    o += '"';
    for (unsigned char c : s) {
        switch (c) {
        case '"': o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        case '\b': o += "\\b"; break;
        case '\f': o += "\\f"; break;
        default:
            if (c < 0x20) {
                char b[8];
                std::snprintf(b, sizeof(b), "\\u%04x", c);
                o += b;
            } else {
                o += char(c);
            }
        }
    }
    o += '"';
}

// serde_json::to_string_pretty: two-space indent, "key": value, empty containers inline.
void pretty(std::string& o, const UniValue& v, int indent)
{
    auto pad = [&](int n) { o.append(size_t(n) * 2, ' '); };
    if (v.isObject()) {
        if (v.empty()) {
            o += "{}";
            return;
        }
        o += "{\n";
        for (size_t i = 0; i < v.size(); i++) {
            pad(indent + 1);
            json_str(o, v.getKeys()[i]);
            o += ": ";
            pretty(o, v.getValues()[i], indent + 1);
            o += i + 1 < v.size() ? ",\n" : "\n";
        }
        pad(indent);
        o += "}";
    } else if (v.isArray()) {
        if (v.empty()) {
            o += "[]";
            return;
        }
        o += "[\n";
        for (size_t i = 0; i < v.size(); i++) {
            pad(indent + 1);
            pretty(o, v[i], indent + 1);
            o += i + 1 < v.size() ? ",\n" : "\n";
        }
        pad(indent);
        o += "]";
    } else if (v.isStr()) {
        json_str(o, v.get_str());
    } else {
        o += v.write();
    }
}

// RFC 8785 (serde_json_canonicalizer): sorted keys, no whitespace.
void canonical(std::string& o, const UniValue& v)
{
    if (v.isObject()) {
        std::vector<size_t> idx(v.size());
        for (size_t i = 0; i < idx.size(); i++) idx[i] = i;
        std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) { return v.getKeys()[a] < v.getKeys()[b]; });
        o += "{";
        for (size_t k = 0; k < idx.size(); k++) {
            if (k) o += ",";
            json_str(o, v.getKeys()[idx[k]]);
            o += ":";
            canonical(o, v.getValues()[idx[k]]);
        }
        o += "}";
    } else if (v.isArray()) {
        o += "[";
        for (size_t i = 0; i < v.size(); i++) {
            if (i) o += ",";
            canonical(o, v[i]);
        }
        o += "]";
    } else if (v.isStr()) {
        json_str(o, v.get_str());
    } else {
        o += v.write();
    }
}

bool parse_url(const std::string& url, std::string& host, uint16_t& port)
{
    std::string r = url;
    if (r.rfind("http://", 0) == 0) r = r.substr(7);
    auto slash = r.find('/');
    if (slash != std::string::npos) r = r.substr(0, slash);
    auto hp = bt::split_hostport(r, uint16_t(80));
    if (!hp) return false;
    host = hp->first;
    port = hp->second;
    return true;
}

int fail(const std::string& m)
{
    std::fprintf(stderr, "Error: %s\n", m.c_str());
    return 1;
}

UniValue rpc(const std::string& host, uint16_t port, const std::string& method, const UniValue& params, std::string& err)
{
    UniValue resp = bt::jsonrpc::call(host, port, method, params, err);
    if (!err.empty()) return UniValue();
    if (!resp["error"].isNull()) {
        err = resp["error"]["message"].getValStr();
        return UniValue();
    }
    return resp["result"];
}

} // namespace

int main(int argc, char** argv)
{
    std::string url = "http://127.0.0.1:6002";
    int i = 1;
    for (; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--rpc-url" && i + 1 < argc) url = argv[++i];
        else if (a.rfind("--rpc-url=", 0) == 0) url = a.substr(10);
        else if (a == "--timeout" && i + 1 < argc) ++i;
        else if (a.rfind("--timeout=", 0) == 0) {
        } else if (a == "-v" || a == "--verbose") {
        } else break;
    }
    auto all = specs();
    if (i >= argc || std::string(argv[i]) == "--help" || std::string(argv[i]) == "help") {
        std::printf("Usage: bitnames-cli [--rpc-url URL] [--timeout SECS] <COMMAND>\n\nCommands:\n");
        for (auto& [k, _] : all) std::printf("  %s\n", k.c_str());
        for (const char* k : {"get-stxos", "get-utxos", "register-bitname", "resolve-commit"}) std::printf("  %s\n", k);
        return argc > i ? 0 : 2;
    }
    if (std::string(argv[i]) == "-V" || std::string(argv[i]) == "--version") {
        std::printf("plain_bitnames_app_cli %s\n", bitnames::VERSION);
        return 0;
    }
    std::string host;
    uint16_t port;
    if (!parse_url(url, host, port)) return fail("invalid --rpc-url");
    std::string cmd = argv[i++];
    UniValue params(UniValue::VOBJ);
    std::string err;
    if (cmd == "get-stxos" || cmd == "get-utxos") {
        UniValue a(UniValue::VARR);
        for (; i < argc; i++) a.push_back(argv[i]);
        if (a.empty()) {
            std::fprintf(stderr, "error: the following required arguments were not provided: <ADDRESSES>...\n");
            return 2;
        }
        params.pushKV("addresses", a);
        UniValue r = rpc(host, port, cmd == "get-stxos" ? "get_stxos" : "get_utxos", params, err);
        if (!err.empty()) return fail(err);
        std::string o;
        pretty(o, r, 0);
        std::printf("%s\n", o.c_str());
        return 0;
    }
    if (cmd == "register-bitname") {
        // RegisterBitname { plaintext_name, #[command(flatten)] MutableBitNameData }
        UniValue data(UniValue::VOBJ);
        std::string name;
        static const std::map<std::string, std::string> fields = {
            {"--commitment", "commitment"}, {"--socket-addr-v4", "socket_addr_v4"}, {"--socket-addr-v6", "socket_addr_v6"},
            {"--encryption-pubkey", "encryption_pubkey"}, {"--signing-pubkey", "signing_pubkey"}, {"--paymail-fee-sats", "paymail_fee_sats"}};
        for (; i < argc; i++) {
            std::string a = argv[i];
            auto it = fields.find(a);
            if (it != fields.end() && i + 1 < argc) {
                std::string v = argv[++i];
                if (it->second == "commitment") {
                    auto h = bt::hex_to_array<32>(v);
                    if (!h) return fail("invalid --commitment");
                    UniValue arr(UniValue::VARR);
                    for (auto b : *h) arr.push_back(int(b));
                    data.pushKV("commitment", arr);
                } else if (it->second == "paymail_fee_sats") {
                    auto n = bt::parse_u64(v);
                    if (!n) return fail("invalid --paymail-fee-sats");
                    data.pushKV("paymail_fee_sats", UniValue(*n));
                } else {
                    data.pushKV(it->second, v);
                }
            } else if (name.empty()) {
                name = a;
            } else {
                std::fprintf(stderr, "error: unexpected argument '%s'\n", a.c_str());
                return 2;
            }
        }
        if (name.empty()) {
            std::fprintf(stderr, "error: the following required arguments were not provided: <PLAINTEXT_NAME>\n");
            return 2;
        }
        params.pushKV("plain_name", name);
        params.pushKV("bitname_data", data);
        UniValue r = rpc(host, port, "register_bitname", params, err);
        if (!err.empty()) return fail(err);
        std::printf("%s\n", r.getValStr().c_str());
        return 0;
    }
    if (cmd == "resolve-commit") {
        // fetch bitname_data, call bitname_commit on the name's socket address, check
        // blake3(RFC 8785 canonical JSON) against the on-chain commitment, print the field
        if (argc - i != 2) {
            std::fprintf(stderr, "error: usage: resolve-commit <BITNAME_ID> <FIELD_NAME>\n");
            return 2;
        }
        params.pushKV("bitname_id", argv[i]);
        UniValue d = rpc(host, port, "bitname_data", params, err);
        if (!err.empty()) return fail(err);
        std::string sock = d["socket_addr_v4"].isStr() ? d["socket_addr_v4"].get_str() : d["socket_addr_v6"].isStr() ? d["socket_addr_v6"].get_str() : "";
        if (sock.empty()) return fail("No IP/port address resolved");
        if (!d["commitment"].isArray() || d["commitment"].size() != 32) return fail("No commitment resolved");
        bt::Hash32 want;
        for (size_t k = 0; k < 32; k++) want[k] = uint8_t(d["commitment"][k].getInt<int>());
        std::string ch;
        uint16_t cp;
        if (!parse_url("http://" + sock, ch, cp)) return fail("bad socket address");
        UniValue nullp(UniValue::VARR);
        nullp.push_back(UniValue());
        UniValue commit = rpc(ch, cp, "bitname_commit", nullp, err);
        if (!err.empty()) return fail(err);
        std::string canon;
        canonical(canon, commit);
        if (bt::blake3(bt::ByteSpan((const uint8_t*)canon.data(), canon.size())) != want) return fail("commitment == canonical_hash");
        std::string o;
        pretty(o, commit[argv[i + 1]], 0);
        std::printf("%s\n", commit.exists(argv[i + 1]) ? o.c_str() : "null");
        return 0;
    }
    auto it = all.find(cmd);
    if (it == all.end()) {
        std::fprintf(stderr, "error: unrecognized subcommand '%s'\n", cmd.c_str());
        return 2;
    }
    const Spec& spec = it->second;
    size_t pos = 0;
    bool utf8 = false;
    for (; i < argc; i++) {
        std::string a = argv[i];
        if (cmd == "decrypt-msg" && a == "--utf8") {
            utf8 = true;
            continue;
        }
        std::string fname, fval;
        bool is_flag = false;
        for (auto& [flag, name] : spec.flags) {
            if (a == flag && i + 1 < argc) {
                fname = name;
                fval = argv[++i];
                is_flag = true;
            } else if (a.rfind(flag + "=", 0) == 0) {
                fname = name;
                fval = a.substr(flag.size() + 1);
                is_flag = true;
            }
            if (is_flag) break;
        }
        std::string name = fname, value = fval;
        if (!is_flag) {
            if (pos >= spec.positional.size()) {
                std::fprintf(stderr, "error: unexpected argument '%s'\n", a.c_str());
                return 2;
            }
            name = spec.positional[pos++];
            value = a;
        }
        bool is_json = std::find(spec.json_args.begin(), spec.json_args.end(), name) != spec.json_args.end();
        UniValue v;
        if (is_json) {
            if (!v.read(value)) {
                std::fprintf(stderr, "error: invalid value '%s' for '<%s>'\n", value.c_str(), name.c_str());
                return 2;
            }
        } else {
            v = UniValue(value);
        }
        params.pushKV(name, v);
    }
    if (cmd == "sign-transaction" && !params.exists("broadcast")) params.pushKV("broadcast", false);
    UniValue r = rpc(host, port, spec.rpc, params, err);
    if (!err.empty()) return fail(err);
    switch (spec.out) {
    case Out::Pretty: {
        std::string o;
        pretty(o, r, 0);
        std::printf("%s\n", o.c_str());
        break;
    }
    case Out::Display:
        if (utf8 && r.isStr()) {
            auto b = bt::hex_decode(r.get_str());
            if (!b) return fail("invalid hex");
            std::printf("%s\n", std::string(b->begin(), b->end()).c_str());
        } else {
            std::printf("%s\n", r.isStr() ? r.get_str().c_str() : r.write().c_str());
        }
        break;
    case Out::Empty: std::printf("\n"); break;
    }
    return 0;
}
