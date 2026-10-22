// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// `bitnames`: drop-in replacement for the plain-bitnames fork's `plain_bitnames_app`
// (v0.18.x, shipped as `bitnames`) on eCash slot 2. Same command-line flags (app/cli.rs),
// defaults (P2P 0.0.0.0:4002, RPC 127.0.0.1:6002, ZMQ 127.0.0.1:28002, datadir
// <data_dir>/plain_bitnames, logs <datadir>/logs/v0.18.2, mainchain 127.0.0.1:50051) and
// JSON-RPC methods. No GUI: without --headless it runs headless. Our own options use the
// --bt- prefix; unknown flags are reported and ignored (the orchestrator stops a daemon that
// fails to parse its arguments).
#include <bitnames/app.h>

#include <bt/frost.h>
#include <bt/fsperm.h>
#include <bt/jsonrpc.h>
#include <bt/log.h>
#include <bt/parse.h>

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <thread>

using namespace bitnames;

static const char* OUR_VERSION = "backbone-bitnames 0.1.0 (plain_bitnames 0.18.2 compatible)";

static std::atomic<bool> g_stop{false};
static void on_signal(int) { g_stop = true; }

static std::string default_datadir()
{
#ifdef _WIN32
    const char* app = std::getenv("APPDATA");
    return std::string(app ? app : ".") + "\\plain_bitnames";
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    return std::string(home ? home : ".") + "/Library/Application Support/plain_bitnames";
#else
    if (const char* x = std::getenv("XDG_DATA_HOME"); x && *x) return std::string(x) + "/plain_bitnames";
    const char* home = std::getenv("HOME");
    return std::string(home ? home : ".") + "/.local/share/plain_bitnames";
#endif
}

static bool parse_sockaddr(const std::string& s, bt::quic::SockAddr& out)
{
    auto hp = bt::split_hostport(s, std::nullopt, true);
    if (!hp) return false;
    out = {hp->first, hp->second};
    return true;
}

static void usage()
{
    std::printf(
        "Usage: bitnames [OPTIONS]\n\n"
        "Options (plain_bitnames 0.18.2 compatible):\n"
        "      --add-peer <ADD_PEERS>                     Additional peers to dial on startup, as host:port\n"
        "  -d, --datadir <DATADIR>                        [default: %s]\n"
        "      --file-log-level <FILE_LOG_LEVEL>          [default: WARN]\n"
        "      --headless                                 Accepted; there is no GUI\n"
        "      --log-dir <LOG_DIR>                        [default: <DATADIR>/logs/v%s]; empty disables file logs\n"
        "      --log-level <LOG_LEVEL>                    [default: DEBUG]\n"
        "      --mainchain-grpc-host <MAINCHAIN_GRPC_HOST> [default: 127.0.0.1]\n"
        "      --mainchain-grpc-port <MAINCHAIN_GRPC_PORT> [default: 50051]\n"
        "      --mnemonic-seed-phrase-path <PATH>         Path to a mnemonic seed phrase\n"
        "  -n, --net-addr <NET_ADDR>                      [default: 0.0.0.0:4002]\n"
        "      --network <NETWORK>                        betanet | forknet | regtest | signet [default: betanet]\n"
        "      --network-magic <NETWORK_MAGIC>            4 bytes as hex\n"
        "  -p, --private-rpc-addr <PRIVATE_RPC_ADDR>      [default: 127.0.0.1:6002]\n"
        "  -r, --rpc-addr <RPC_ADDR>                      [default: 127.0.0.1:6002]\n"
        "      --server-name <SERVER_NAMES>               Host name for the P2P certificate (repeatable)\n"
        "      --wallet-dir <WALLET_DIR>                  [default: <DATADIR>]\n"
        "  -z, --zmq-addr <ZMQ_ADDR>                      [default: 127.0.0.1:28002]\n"
        "  -h, --help / -V, --version\n\n"
        "Backbone options:\n"
        "      --bt-mainchain-grpc-url <URL>              Full URL instead of host/port (https:// for TLS)\n"
        "      --bt-rpc-allowed-origin <ORIGIN>           Allow browser requests from this Origin (repeatable; \"*\" = any)\n"
        "      --bt-rpc-allowed-host <HOST>               Extra Host header name accepted by the RPC server\n"
        "      --bt-rpc-allow-external                    Allow binding the unauthenticated RPC to a non-loopback address\n"
        "      --bt-no-seeds                              Do not dial the built-in seed peers\n"
        "      --bt-rebuild-side-tips                     Rebuild the side-tips index from the mainchain at start\n"
        "      --bt-no-p2p                                Disable P2P networking\n"
        "      --bt-no-zmq                                Do not bind the ZMQ publisher\n",
        default_datadir().c_str(), VERSION);
}

int main(int argc, char** argv)
{
#ifndef _WIN32
    // A gRPC (TLS) or RPC peer that goes away must not kill the node with SIGPIPE: a stopped
    // or restarting enforcer did exactly that (found by the zSide drop-in, regtest 2026-10-22).
    std::signal(SIGPIPE, SIG_IGN);
#endif
    NodeConfig cfg;
    cfg.datadir = default_datadir();
    std::optional<std::string> log_dir, wallet_dir, mnemonic_path, grpc_url;
    std::string grpc_host = "127.0.0.1";
    uint16_t grpc_port = 50051;
    bt::log::Level log_level = bt::log::Level::Debug, file_log_level = bt::log::Level::Warn;
    bt::quic::SockAddr rpc_addr{"127.0.0.1", DEFAULT_RPC_PORT}, private_rpc_addr = rpc_addr, zmq_addr{"127.0.0.1", DEFAULT_ZMQ_PORT};
    bool headless = false, no_zmq = false;
    std::vector<std::string> unknown;
    bt::jsonrpc::Options rpc_opts;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i], val;
        bool has_eq = false;
        if (a.rfind("--", 0) == 0) {
            auto eq = a.find('=');
            if (eq != std::string::npos) {
                val = a.substr(eq + 1);
                a = a.substr(0, eq);
                has_eq = true;
            }
        } else if (a.size() > 2 && a[0] == '-' && a[1] != '-') { // -dVALUE
            val = a.substr(2);
            a = a.substr(0, 2);
            has_eq = true;
        }
        auto next = [&](std::string& out) -> bool {
            if (has_eq) {
                out = val;
                return true;
            }
            if (i + 1 < argc) {
                out = argv[++i];
                return true;
            }
            std::fprintf(stderr, "error: a value is required for '%s'\n", a.c_str());
            return false;
        };
        std::string v;
        if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else if (a == "-V" || a == "--version") {
            std::printf("plain_bitnames_app %s\n%s\n", VERSION, OUR_VERSION);
            return 0;
        } else if (a == "--add-peer") {
            if (!next(v)) return 2;
            if (!bt::split_hostport(v, DEFAULT_PORT)) {
                std::fprintf(stderr, "error: invalid value '%s' for '--add-peer'\n", v.c_str());
                return 2;
            }
            cfg.add_peers.push_back(v);
        } else if (a == "-d" || a == "--datadir") {
            if (!next(v)) return 2;
            cfg.datadir = v;
        } else if (a == "--headless") {
            headless = true;
        } else if (a == "--log-dir") {
            if (!next(v)) return 2;
            log_dir = v;
        } else if (a == "--log-level" || a == "--file-log-level") {
            if (!next(v)) return 2;
            auto l = bt::log::parse_level(v);
            if (!l) {
                std::fprintf(stderr, "error: invalid value '%s' for '%s'\n", v.c_str(), a.c_str());
                return 2;
            }
            (a == "--log-level" ? log_level : file_log_level) = *l;
        } else if (a == "--mainchain-grpc-host") {
            if (!next(v) || v.empty()) return 2;
            grpc_host = v;
        } else if (a == "--mainchain-grpc-port") {
            if (!next(v)) return 2;
            auto p = bt::parse_port(v, true);
            if (!p) {
                std::fprintf(stderr, "error: invalid value '%s' for '--mainchain-grpc-port'\n", v.c_str());
                return 2;
            }
            grpc_port = *p;
        } else if (a == "--bt-mainchain-grpc-url") {
            if (!next(v)) return 2;
            grpc_url = v;
        } else if (a == "--mnemonic-seed-phrase-path") {
            if (!next(v)) return 2;
            mnemonic_path = v;
        } else if (a == "-n" || a == "--net-addr") {
            if (!next(v) || !parse_sockaddr(v, cfg.net_addr)) {
                std::fprintf(stderr, "error: invalid value for '--net-addr'\n");
                return 2;
            }
        } else if (a == "--network") {
            if (!next(v)) return 2;
            if (v == "betanet") cfg.network = Network::Betanet;
            else if (v == "forknet") cfg.network = Network::Forknet;
            else if (v == "regtest") cfg.network = Network::Regtest;
            else if (v == "signet") cfg.network = Network::Signet;
            else {
                std::fprintf(stderr, "error: invalid value '%s' for '--network'\n", v.c_str());
                return 2;
            }
        } else if (a == "--network-magic") {
            if (!next(v)) return 2;
            auto m = bt::hex_decode(v);
            if (!m || m->size() != 4) {
                std::fprintf(stderr, "error: invalid value '%s' for '--network-magic'\n", v.c_str());
                return 2;
            }
            cfg.magic_override = std::array<uint8_t, 4>{(*m)[0], (*m)[1], (*m)[2], (*m)[3]};
        } else if (a == "-p" || a == "--private-rpc-addr") {
            if (!next(v) || !parse_sockaddr(v, private_rpc_addr)) return 2;
        } else if (a == "-r" || a == "--rpc-addr") {
            if (!next(v) || !parse_sockaddr(v, rpc_addr)) return 2;
        } else if (a == "-z" || a == "--zmq-addr") {
            if (!next(v) || !parse_sockaddr(v, zmq_addr)) return 2;
        } else if (a == "--server-name") {
            if (!next(v)) return 2;
            cfg.server_names.push_back(v);
        } else if (a == "--wallet-dir") {
            if (!next(v)) return 2;
            wallet_dir = v;
        } else if (a == "--bt-rpc-allowed-origin") {
            if (!next(v)) return 2;
            rpc_opts.allowed_origins.push_back(v);
        } else if (a == "--bt-rpc-allowed-host") {
            if (!next(v)) return 2;
            rpc_opts.allowed_hosts.push_back(v);
        } else if (a == "--bt-rpc-allow-external") {
            rpc_opts.allow_external = true;
        } else if (a == "--bt-no-seeds") {
            cfg.use_seeds = false;
        } else if (a == "--bt-rebuild-side-tips") {
            cfg.rebuild_side_tips = true;
        } else if (a == "--bt-no-p2p") {
            cfg.p2p = false;
        } else if (a == "--bt-no-zmq") {
            no_zmq = true;
        } else {
            unknown.push_back(argv[i]);
        }
    }
    bool v6host = grpc_host.find(':') != std::string::npos && grpc_host[0] != '[';
    cfg.mainchain_grpc_url = grpc_url ? *grpc_url : "http://" + (v6host ? "[" + grpc_host + "]" : grpc_host) + ":" + std::to_string(grpc_port);
    if (!no_zmq) cfg.zmq_addr = zmq_addr;
    // cli.rs get_config: without --headless the console level drops one step (GUI default)
    if (!headless && log_level != bt::log::Level::Error) log_level = bt::log::Level(int(log_level) - 1);
    std::string logs = log_dir ? *log_dir : cfg.datadir + "/logs/v" + VERSION;
    bt::log::set_console_level(log_level);
    bt::log::set_file(logs, file_log_level);
    for (auto& u : unknown) LOG_WARN("ignoring unknown argument '%s'", u.c_str());
    if (!headless) LOG_INFO("no GUI in this build; running headless");
    LOG_INFO("%s starting: datadir %s, network magic override %s, mainchain %s", OUR_VERSION, cfg.datadir.c_str(),
             cfg.magic_override ? "yes" : "no", cfg.mainchain_grpc_url.c_str());

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    bt::frost::init();
    std::string wdir = wallet_dir ? *wallet_dir : cfg.datadir;
    if (!bt::fsperm::private_dir(cfg.datadir) || !bt::fsperm::private_dir(wdir)) { // the wallet holds the seed
        LOG_ERROR("cannot create %s / %s", cfg.datadir.c_str(), wdir.c_str());
        return 1;
    }
    Node node(cfg);
    std::unique_ptr<Wallet> wallet;
    try {
        wallet = std::make_unique<Wallet>(wdir + "/backbone-wallet.sqlite", node);
        if (mnemonic_path) {
            std::ifstream f(*mnemonic_path);
            std::string m((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            wallet->set_seed_from_mnemonic(m);
        }
    } catch (const std::exception& e) {
        LOG_ERROR("wallet: %s", e.what());
        return 1;
    }
    std::string err;
    if (!node.start(err)) {
        LOG_ERROR("startup failed: %s", err.c_str());
        return 1;
    }
    App app(node, *wallet);
    app.on_stop = [] { g_stop = true; };
    bt::jsonrpc::Server pub, priv;
    pub.options = priv.options = rpc_opts;
    if (private_rpc_addr == rpc_addr) {
        register_rpc(pub, app, true, true);
        if (!pub.listen(rpc_addr.ip, rpc_addr.port, err)) {
            LOG_ERROR("%s", err.c_str());
            node.stop();
            return 1;
        }
    } else {
        register_rpc(pub, app, true, false);
        register_rpc(priv, app, false, true);
        if (!pub.listen(rpc_addr.ip, rpc_addr.port, err) || !priv.listen(private_rpc_addr.ip, private_rpc_addr.port, err)) {
            LOG_ERROR("%s", err.c_str());
            node.stop();
            return 1;
        }
    }
    LOG_INFO("JSON-RPC on %s (%zu methods)", rpc_addr.to_string().c_str(), pub.methods().size());
    while (!g_stop) std::this_thread::sleep_for(std::chrono::milliseconds(200));
    LOG_INFO("shutting down");
    pub.stop();
    priv.stop();
    node.stop();
    return 0;
}
