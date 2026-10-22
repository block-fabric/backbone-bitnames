// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <bitnames/appui.h>
#include <bitnames/json.h>

#include <bt/appui/phrase.h>
#include <bt/fsperm.h>
#include <bt/hd.h>
#include <bt/log.h>

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <set>

namespace bitnames {

using bt::appui::Confirmed;
using bt::appui::HostEnv;
using bt::appui::HostError;
using bt::appui::Question;
using bt::appui::Row;
using bt::appui::RpcError;

namespace {
const char* WALLET_NAME = "main";
/** The LayerTwo read that stands for knowing the wallet's addresses: what tells a caller which outputs are the wallet's. */
const char* WALLET_READ = "get_wallet_addresses";
const char* VERSION_TEXT = "0.1.0 (plain_bitnames 0.18.2 compatible)";

const UniValue NULLV;
const UniValue& param(const UniValue& p, const std::string& key) { return p.isObject() ? p.find_value(key) : NULLV; }

std::string str_param(const UniValue& p, const std::string& key)
{
    const UniValue& v{param(p, key)};
    if (!v.isStr()) throw HostError(bt::appui::HOST_INVALID_REQUEST, key + ": a string is needed");
    return v.get_str();
}

uint64_t u64_of(const UniValue& v, const std::string& what)
{
    if (!v.isNum()) throw HostError(bt::appui::HOST_INVALID_REQUEST, what + ": a whole number of satoshis is needed");
    const std::string s{v.getValStr()};
    if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos) throw HostError(bt::appui::HOST_INVALID_REQUEST, what + ": a whole number of satoshis is needed");
    auto n{bt::parse_u64(s)};
    if (!n) throw HostError(bt::appui::HOST_INVALID_REQUEST, what + ": too large");
    return *n;
}

std::string coins(uint64_t sats) { return bt::appui::format_sats(sats) + " ECX"; }

bool is_value(const FilledOutput& o) { return o.content.kind == FilledContent::Bitcoin; }

std::string net_label(const std::string& network) { return network == "betanet" ? "" : network; }

/** Whether a mainchain address is of the mainchain network this node follows (betanet and forknet follow eCash's
 *  betanet, whose addresses are Bitcoin's main ones; regtest's are regtest ones, signet's test ones). */
bool main_address_of_network(const bt::btc::Address& a, const std::string& network)
{
    using A = bt::btc::Address;
    if (a.kind == A::Kind::Segwit) {
        if (network == "regtest") return a.hrp == A::Hrp::Regtest;
        if (network == "signet") return a.hrp == A::Hrp::Testnets;
        return a.hrp == A::Hrp::Mainnet;
    }
    if (network == "regtest" || network == "signet") return a.net == A::NetKind::Test;
    return a.net == A::NetKind::Main;
}

UniValue n64(uint64_t v) { return UniValue(v); }
} // namespace

struct AppLayer::Impl {
    App& app;
    Node& node;
    Wallet& wallet;
    std::string network, datadir;
    bt::appui::AppOptions options;
    bt::jsonrpc::Server l2l;
    std::unique_ptr<bt::appui::AppStore> store;
    std::unique_ptr<bt::appui::LinkMonitor> link;
    std::unique_ptr<bt::appui::Poller> poller;
    bt::appui::PendingPhrases phrases;
    std::chrono::system_clock::time_point started{std::chrono::system_clock::now()};

    Impl(App& a, std::string net, std::string dir, bt::appui::AppOptions o)
        : app(a), node(a.node), wallet(a.wallet), network(std::move(net)), datadir(std::move(dir)), options(std::move(o))
    {
        // Every LayerTwo method, on a server that does not listen: the reads the pages make and the spends run after
        // a yes go through the very handlers (and JSON) of the LayerTwo RPC.
        register_rpc(l2l, app, true, true);
    }

    /** One LayerTwo method, through its own handler: its result, or its error as an app RPC error. */
    UniValue l2l_call(const std::string& method, const UniValue& params)
    {
        UniValue req{UniValue::VOBJ};
        req.pushKV("jsonrpc", "2.0");
        req.pushKV("id", 1);
        req.pushKV("method", method);
        req.pushKV("params", params.isNull() ? UniValue{UniValue::VARR} : params);
        UniValue resp;
        if (!resp.read(l2l.handle(req.write())) || !resp.isObject()) throw RpcError(bt::appui::RPC_INTERNAL_ERROR, "no answer from " + method);
        const UniValue& err{resp.find_value("error")};
        if (err.isObject()) {
            const UniValue& data{err.find_value("data")};
            throw RpcError(err.find_value("code").isNum() ? err.find_value("code").getInt<int>() : -1,
                           err.find_value("message").getValStr() + (data.isStr() ? ": " + data.get_str() : std::string{}));
        }
        return resp.find_value("result");
    }

    std::set<Address> addresses()
    {
        auto a{wallet.addresses()};
        return {a.begin(), a.end()};
    }

    std::optional<std::pair<uint32_t, Hash32>> block_of(const Hash32& block)
    {
        auto h{node.block_height(block)};
        auto hd{node.header(block)};
        if (!h || !hd) return std::nullopt;
        return std::make_pair(*h, hd->prev_main_hash);
    }

    std::optional<uint64_t> main_time(const Hash32& main) { return link ? link->block_time(main) : std::nullopt; }

    std::optional<std::pair<Hash32, std::optional<uint32_t>>> followed()
    {
        auto tip{node.tip()};
        if (!tip) return std::nullopt;
        auto hd{node.header(*tip)};
        if (!hd) return std::nullopt;
        return std::make_pair(hd->prev_main_hash, link ? link->block_height(hd->prev_main_hash) : std::nullopt);
    }

    // ---------------------------------------------------------- wallet
    struct Balances {
        uint64_t available{0}, withdrawing{0}, pending_in{0}, pending_out{0};
    };

    Balances balances(const std::set<Address>& mine)
    {
        Balances b;
        for (auto& [op, o] : node.utxos_by_addresses(mine)) {
            if (o.content.is_withdrawal()) b.withdrawing += o.get_value();
            else if (is_value(o)) b.available += o.get_value();
        }
        auto [txs, fees] = node.mempool_transactions(1000);
        (void)fees;
        for (auto& [atx, spent] : txs) {
            for (const FilledOutput& s : spent) {
                if (mine.contains(s.address) && is_value(s)) b.pending_out += s.get_value();
            }
            for (const Output& o : atx.transaction.outputs) {
                if (mine.contains(o.address) && o.content.kind == Content::Bitcoin) b.pending_in += o.get_value();
            }
        }
        return b;
    }

    std::string wallet_id()
    {
        // The fingerprint of the seed, or none: a token for one wallet is never taken for another.
        return seed_fingerprint();
    }

    /** bt::appui::seed_fingerprint of the wallet's seed (the same definition), "" without one. */
    std::string seed_fingerprint()
    {
        auto d{wallet.seed_digest("sidechain/dropin/fingerprint/v1")};
        return d ? bt::hex_encode(bt::ByteSpan{d->data(), 8}) : std::string{};
    }

    /** Set the wallet's seed from a phrase checked before; the phrase kept for the backup (owner-only store). */
    UniValue set_phrase(const std::string& phrase, const std::string& from)
    {
        auto p{bt::hd::parse_mnemonic(phrase)};
        if (!p) throw HostError(bt::hd::mnemonic_error(phrase));
        auto seed{bt::hd::mnemonic_to_seed(*p)};
        const std::string fp{bt::appui::seed_fingerprint(seed.span())};
        try {
            wallet.set_seed(seed);
        } catch (const std::exception& e) {
            sodium_memzero(seed.data(), seed.size());
            throw HostError(bt::appui::RPC_WALLET_ERROR, std::string{"This wallet has a backup phrase already ("} + e.what() + ")");
        }
        sodium_memzero(seed.data(), seed.size());
        store->put("phrase", *p);
        store->put("phrase.from", from);
        if (poller) poller->poke();
        UniValue out{UniValue::VOBJ};
        out.pushKV("fingerprint", fp);
        return out;
    }

    /** The phrase the app layer kept, only when it is the one of the wallet's seed now (a wallet file replaced since: none). */
    std::optional<std::string> kept_phrase()
    {
        auto phrase{store->get("phrase")};
        if (!phrase || !wallet.has_seed()) return std::nullopt;
        auto p{bt::hd::parse_mnemonic(*phrase)};
        if (!p) return std::nullopt;
        auto seed{bt::hd::mnemonic_to_seed(*p)};
        const bool same{bt::appui::seed_fingerprint(seed.span()) == seed_fingerprint()};
        sodium_memzero(seed.data(), seed.size());
        if (!same) {
            sodium_memzero(phrase->data(), phrase->size());
            return std::nullopt;
        }
        return phrase;
    }

    UniValue seed_status()
    {
        UniValue s{UniValue::VOBJ};
        const bool has{wallet.has_seed()};
        s.pushKV("hasSeed", has);
        s.pushKV("phraseKept", has && kept_phrase().has_value());
        s.pushKV("from", has ? store->get("phrase.from").value_or("outside") : "");
        s.pushKV("fingerprint", has ? seed_fingerprint() : "");
        s.pushKV("derivation", "plain_bitnames");
        return s;
    }

    static std::string words_block(const std::string& phrase)
    {
        std::string out;
        size_t n{0}, at{0};
        while (at < phrase.size()) {
            size_t sp{phrase.find(' ', at)};
            if (sp == std::string::npos) sp = phrase.size();
            ++n;
            out += (n < 10 ? " " : "") + std::to_string(n) + ". " + phrase.substr(at, sp - at) + (n % 3 == 0 ? "\n" : "    ");
            at = sp + 1;
        }
        return out;
    }

    // ---------------------------------------------------------- history
    struct Hist {
        std::string id, kind;
        int64_t delta{0};
        uint64_t received{0}, spent{0}, withdrawing{0};
        bool pending{false}, ours_in{false};
        std::optional<Hash32> txid, block, m6id;
        std::vector<std::pair<std::string, uint64_t>> to; // outputs to others
        std::optional<uint64_t> fee;
        std::string main_address;
        //! The wallet's address it paid (what a receipt was received at).
        std::string own_address;
        std::vector<std::string> names; // BitNames that came with it (registered or received)
        bool reservation{false};
        std::string reserved; // the name a reservation of the wallet commits to, in words
    };

    /** The block of the active chain a transaction is in. */
    std::optional<Hash32> block_of_tx(const Hash32& txid)
    {
        for (auto& [blk, idx] : node.tx_inclusions(txid)) {
            auto h{node.block_height(blk)};
            if (h && node.block_hash_at(*h) == blk) return blk;
        }
        return std::nullopt;
    }

    std::optional<std::pair<Hash32, BundleStatus>> bundle_status(const Hash32& m6id)
    {
        std::lock_guard<std::recursive_mutex> l(node.lock());
        bt::kv::Txn t(node.store());
        auto b{node.state().bundle(t, m6id)};
        if (!b) return std::nullopt;
        return std::make_pair(m6id, b->second.latest().value);
    }

    std::string name_text(const Hash32& name)
    {
        auto plain{wallet.plain_name(name)};
        return plain ? *plain : bt::hex_encode(name);
    }

    std::string seen_key(const std::string& id) { return "seen:" + id; }

    std::optional<std::pair<int64_t, int64_t>> seen(const std::string& id)
    {
        auto v{store->get(seen_key(id))};
        if (!v) return std::nullopt;
        const size_t c{v->find(':')};
        if (c == std::string::npos) return std::nullopt;
        return std::make_pair(std::atoll(v->substr(0, c).c_str()), std::atoll(v->substr(c + 1).c_str()));
    }

    void note_seen(const std::string& id)
    {
        if (store->get(seen_key(id))) return;
        auto h{node.height()};
        const int64_t now{std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()};
        store->put(seen_key(id), std::to_string(h ? int64_t(*h) : int64_t{-1}) + ":" + std::to_string(now));
    }

    std::map<std::string, Hist> gather(const std::set<Address>& mine)
    {
        std::map<std::string, Hist> rows;
        auto row_of = [&](const OutPoint& op) -> Hist& {
            std::string id;
            std::string kind;
            if (op.kind == OutPoint::Deposit) {
                id = "deposit:" + bt::hex_encode_rev(op.txid.span());
                kind = "deposit";
            } else if (op.kind == OutPoint::Coinbase) {
                id = "coinbase:" + bt::hex_encode(op.txid);
                kind = "mined";
            } else {
                id = bt::hex_encode(op.txid);
            }
            Hist& h{rows[id]};
            if (h.id.empty()) {
                h.id = id;
                h.kind = kind;
                if (op.kind == OutPoint::Regular) h.txid = op.txid;
            }
            return h;
        };
        auto credit = [&](const OutPoint& op, const FilledOutput& o) {
            Hist& h{row_of(op)};
            if (o.content.is_withdrawal()) {
                h.withdrawing += o.get_value();
                h.main_address = o.content.main_address.to_string();
            } else if (o.content.is_bitname()) {
                h.names.push_back(name_text(o.content.bitname));
            } else if (o.content.is_reservation()) {
                h.reservation = true;
                if (auto plain{wallet.reserved_name(o.content.reservation_commitment)}) h.reserved = *plain;
            } else {
                h.received += o.get_value();
                h.delta += static_cast<int64_t>(o.get_value());
                if (h.own_address.empty()) h.own_address = o.address.to_base58();
            }
        };
        for (auto& [op, o] : node.utxos_by_addresses(mine)) credit(op, o);
        for (auto& [op, s] : node.stxos_by_addresses(mine)) {
            credit(op, s.output);
            std::string id;
            if (s.inpoint.kind == InPoint::Withdrawal) {
                id = "bundle:" + bt::hex_encode_rev(s.inpoint.id.span());
                Hist& h{rows[id]};
                if (h.id.empty()) {
                    h.id = id;
                    h.kind = "bundle";
                    h.m6id = s.inpoint.id;
                }
                // Our withdrawal paid out of the chain into a bundle: counted when it was asked for.
                if (s.output.content.is_withdrawal()) h.withdrawing += s.output.get_value();
                else if (is_value(s.output)) {
                    h.spent += s.output.get_value();
                    h.delta -= static_cast<int64_t>(s.output.get_value());
                }
                continue;
            }
            id = bt::hex_encode(s.inpoint.id);
            Hist& h{rows[id]};
            if (h.id.empty()) {
                h.id = id;
                h.txid = s.inpoint.id;
            }
            h.ours_in = true;
            if (is_value(s.output)) {
                h.spent += s.output.get_value();
                h.delta -= static_cast<int64_t>(s.output.get_value());
            }
        }
        // What waits in the mempool: our spends and what comes in.
        auto [txs, fees] = node.mempool_transactions(1000);
        (void)fees;
        for (auto& [atx, spent] : txs) {
            const Transaction& tx{atx.transaction};
            const Hash32 txid{tx.txid()};
            bool touches{false};
            for (const FilledOutput& s : spent) touches = touches || mine.contains(s.address);
            for (const Output& o : tx.outputs) touches = touches || mine.contains(o.address);
            if (!touches) continue;
            Hist& h{rows[bt::hex_encode(txid)]};
            h.id = bt::hex_encode(txid);
            h.txid = txid;
            h.pending = true;
            h.received = h.spent = h.withdrawing = 0;
            h.delta = 0;
            uint64_t in_total{0}, out_total{0};
            bool all_inputs_ours{true};
            for (const FilledOutput& s : spent) {
                in_total += s.get_value();
                if (mine.contains(s.address)) {
                    h.ours_in = true;
                    if (is_value(s)) {
                        h.spent += s.get_value();
                        h.delta -= static_cast<int64_t>(s.get_value());
                    }
                } else {
                    all_inputs_ours = false;
                }
            }
            h.to.clear();
            for (const Output& o : tx.outputs) {
                out_total += o.get_value();
                if (mine.contains(o.address)) {
                    if (o.content.kind == Content::Withdrawal) {
                        h.withdrawing += o.get_value();
                        h.main_address = o.content.main_address.to_string();
                    } else if (o.content.kind == Content::BitNameReservation) {
                        h.reservation = true;
                        if (tx.data && tx.data->kind == TxData::Reservation) {
                            if (auto plain{wallet.reserved_name(tx.data->commitment)}) h.reserved = *plain;
                        }
                    } else if (o.content.kind == Content::BitName) {
                        h.names.push_back("(a name)");
                    } else {
                        h.received += o.get_value();
                        h.delta += static_cast<int64_t>(o.get_value());
                        if (h.own_address.empty()) h.own_address = o.address.to_base58();
                    }
                } else {
                    h.to.emplace_back(o.address.to_base58(), o.get_value());
                }
            }
            if (all_inputs_ours && in_total >= out_total) h.fee = in_total - out_total;
        }
        return rows;
    }

    UniValue history(size_t limit)
    {
        const auto mine{addresses()};
        auto rows{gather(mine)};
        struct Out {
            UniValue v;
            int64_t order_height;
            int64_t order_time;
        };
        std::vector<Out> list;
        for (auto& [id, h] : rows) {
            note_seen(id);
            std::optional<uint32_t> height;
            std::optional<uint64_t> time;
            std::string block_hex;
            // A transaction of a block: where, when (the time of the mainchain block it was merged-mined in), its other
            // outputs and its fee.
            if (h.txid && !h.pending) {
                if (auto t{node.transaction(*h.txid)}) {
                    if (auto blk{block_of_tx(*h.txid)}) {
                        block_hex = bt::hex_encode(*blk);
                        if (auto b{block_of(*blk)}) {
                            height = b->first;
                            time = main_time(b->second);
                        }
                    }
                    h.to.clear();
                    uint64_t out_total{0};
                    for (const Output& o : t->outputs) {
                        out_total += o.get_value();
                        if (!mine.contains(o.address) && o.content.kind == Content::Bitcoin) h.to.emplace_back(o.address.to_base58(), o.get_value());
                    }
                    // Every input ours (what we spent of value and withdrawals is the whole input): the fee.
                    if (h.ours_in && t->inputs.size() > 0 && h.spent >= out_total) h.fee = h.spent - out_total;
                }
            }
            bool approx{false};
            if (!height || !time) {
                if (auto s{seen(id)}) {
                    if (!height && s->first >= 0) height = static_cast<uint32_t>(s->first);
                    if (!time) time = static_cast<uint64_t>(s->second);
                    approx = true;
                }
            }
            std::string kind{h.kind};
            if (kind.empty()) {
                if (h.reservation && h.names.empty() && h.delta <= 0) kind = "reservation";
                else if (!h.names.empty() && h.ours_in) kind = "name";
                else if (!h.names.empty()) kind = "name-received";
                else if (h.withdrawing > 0) kind = "withdrawal";
                else if (!h.ours_in) kind = "receive";
                else if (h.to.empty()) kind = "self";
                else kind = "send";
            }
            UniValue o{UniValue::VOBJ};
            o.pushKV("id", id);
            o.pushKV("kind", kind);
            if (h.txid) o.pushKV("txid", bt::hex_encode(*h.txid));
            if (h.m6id) {
                o.pushKV("m6id", bt::hex_encode_rev(h.m6id->span()));
                if (auto b{bundle_status(*h.m6id)}) o.pushKV("bundleStatus", to_string(b->second));
            }
            if (!h.names.empty()) {
                UniValue names{UniValue::VARR};
                for (const auto& n : h.names) names.push_back(n);
                o.pushKV("names", names);
            }
            o.pushKV("amount", static_cast<int64_t>(h.delta));
            o.pushKV("received", n64(h.received));
            o.pushKV("sent", n64(h.spent));
            if (h.withdrawing) o.pushKV("withdrawing", n64(h.withdrawing));
            if (!h.main_address.empty()) o.pushKV("mainAddress", h.main_address);
            if (!h.own_address.empty()) o.pushKV("ownAddress", h.own_address);
            if (!h.reserved.empty()) o.pushKV("reservedName", h.reserved);
            if (h.fee) o.pushKV("fee", n64(*h.fee));
            UniValue to{UniValue::VARR};
            for (auto& [a, v] : h.to) {
                UniValue t{UniValue::VOBJ};
                t.pushKV("address", a);
                t.pushKV("amount", n64(v));
                to.push_back(t);
                if (to.size() >= 50) break;
            }
            o.pushKV("to", to);
            o.pushKV("recipients", static_cast<uint64_t>(h.to.size()));
            o.pushKV("pending", h.pending);
            o.pushKV("height", height ? UniValue(uint64_t(*height)) : UniValue{});
            o.pushKV("time", time ? UniValue(*time) : UniValue{});
            o.pushKV("approxTime", approx);
            if (!block_hex.empty()) o.pushKV("block", block_hex);
            list.push_back(Out{o, h.pending ? INT64_MAX : height ? int64_t(*height) : -1, time ? int64_t(*time) : 0});
        }
        std::sort(list.begin(), list.end(), [](const Out& a, const Out& b) {
            if (a.order_height != b.order_height) return a.order_height > b.order_height;
            if (a.order_time != b.order_time) return a.order_time > b.order_time;
            return a.v.find_value("id").get_str() < b.v.find_value("id").get_str();
        });
        UniValue out{UniValue::VARR};
        for (auto& o : list) {
            if (out.size() >= limit) break;
            out.push_back(std::move(o.v));
        }
        return out;
    }

    // ---------------------------------------------------------- the node as events
    bt::appui::NodeLook look()
    {
        bt::appui::NodeLook l;
        l.height = node.height();
        if (auto t{node.tip()}) {
            l.tip = bt::hex_encode(*t);
            if (auto hd{node.header(*t)}) {
                if (auto tm{main_time(hd->prev_main_hash)}) l.tip_time = *tm;
            }
        }
        // In step with eCash: as fresh as eCash's tip (blocks of this chain come only when merge-mined); behind it, as old
        // as what this chain last acted on.
        if (link && link->connected() && link->info().find_value("state").getValStr() == "ok") {
            if (auto tm{link->tip_time()}) l.tip_time = std::max(l.tip_time, *tm);
        }
        for (auto& p : node.peers()) l.connections += p.connected ? 1 : 0;
        l.wallet = wallet.has_seed();
        if (l.wallet) {
            const auto mine{addresses()};
            const Balances b{balances(mine)};
            l.trusted = b.available;
            l.pending = b.pending_in;
            l.immature = b.withdrawing;
            for (auto& [id, h] : gather(mine)) {
                l.txs[id] = !h.pending;
                note_seen(id);
            }
        }
        if (link && !link->connected()) l.warnings.push_back("The mainchain interface does not answer: this chain cannot follow it.");
        return l;
    }

    UniValue info()
    {
        UniValue i{UniValue::VOBJ};
        i.pushKV("name", "BitNames");
        i.pushKV("version", VERSION_TEXT);
        i.pushKV("bugreport", "https://github.com/block-fabric/backbone-bitnames/issues");
        i.pushKV("network", network);
        i.pushKV("networkLabel", net_label(network));
        i.pushKV("datadir", "");
        i.pushKV("blockSpacing", 600);
        i.pushKV("walletEnabled", true);
        i.pushKV("devtools", false);
        i.pushKV("language", "");
        i.pushKV("test", false);
        i.pushKV("platform", "other");
        i.pushKV("dropin", "bitnames");
        i.pushKV("slot", static_cast<int>(THIS_SIDECHAIN));
        return i;
    }

    // ---------------------------------------------------------- explorer
    UniValue block_summary(uint32_t height, const Hash32& hash, const Header& hd, const Body& b)
    {
        UniValue o{UniValue::VOBJ};
        o.pushKV("height", static_cast<uint64_t>(height));
        o.pushKV("hash", bt::hex_encode(hash));
        o.pushKV("mainHash", bt::hex_encode_rev(hd.prev_main_hash.span()));
        if (auto t{main_time(hd.prev_main_hash)}) o.pushKV("time", *t);
        uint64_t fees{0};
        for (const Output& c : b.coinbase.outputs) fees += c.get_value();
        o.pushKV("txs", static_cast<uint64_t>(b.transactions.size()));
        o.pushKV("inputs", static_cast<uint64_t>(b.inputs_len()));
        size_t outs{0};
        for (const auto& tx : b.transactions) outs += tx.outputs.size();
        o.pushKV("outputs", static_cast<uint64_t>(outs));
        o.pushKV("fees", n64(fees));
        o.pushKV("bytes", static_cast<uint64_t>(borsh_bytes(b).size()));
        // BitNames has no limit of a block's body (it has its sigops' one): none drawn.
        o.pushKV("limit", 0);
        (void)height;
        return o;
    }

    /** Which addresses are the wallet's, for a caller that may read the wallet's addresses; nothing for another (its chain
     *  reads must not tell it which outputs are the wallet's). */
    using Mine = std::optional<std::set<Address>>;
    Mine mine_for(HostEnv& env) { return env.may_call(WALLET_READ) ? Mine{addresses()} : std::nullopt; }

    UniValue output_json(const Output& o, const Mine& mine)
    {
        UniValue r{UniValue::VOBJ};
        r.pushKV("address", o.address.to_base58());
        r.pushKV("amount", n64(o.get_value()));
        const Content::Kind k{o.content.kind};
        r.pushKV("kind", k == Content::Withdrawal ? "withdrawal" : k == Content::BitName ? "name" : k == Content::BitNameReservation ? "reservation" : "value");
        if (k == Content::Withdrawal) {
            r.pushKV("mainAddress", o.content.main_address.to_string());
            r.pushKV("mainFee", n64(o.content.main_fee));
        }
        if (!o.memo.empty()) r.pushKV("memo", bt::hex_encode(o.memo));
        if (mine) r.pushKV("mine", mine->contains(o.address));
        return r;
    }

    UniValue output_json(const FilledOutput& o, const Mine& mine)
    {
        UniValue r{output_json(o.to_output(), mine)};
        if (o.content.is_bitname()) {
            r.pushKV("name", bt::hex_encode(o.content.bitname));
            // The name in words only to a reader of the wallet (the wallet knows the names it reserved).
            if (mine) {
                if (auto plain{wallet.plain_name(o.content.bitname)}) r.pushKV("plainName", *plain);
            }
        }
        return r;
    }

    std::optional<Hash32> parse_hash(const std::string& s)
    {
        auto b{bt::hex_to_array<32>(s)};
        if (!b) return std::nullopt;
        return Hash32{*b};
    }

    UniValue block_detail(const Hash32& hash, const Mine& mine)
    {
        auto hd{node.header(hash)};
        auto b{node.body(hash)};
        auto at{block_of(hash)};
        if (!hd || !b || !at) throw HostError("No such block");
        UniValue o{block_summary(at->first, hash, *hd, *b)};
        o.pushKV("prevHash", hd->prev_side_hash ? bt::hex_encode(*hd->prev_side_hash) : "");
        o.pushKV("merkleRoot", bt::hex_encode(hd->merkle_root));
        o.pushKV("onChain", node.block_hash_at(at->first) == hash);
        UniValue cb{UniValue::VARR};
        for (const Output& c : b->coinbase.outputs) cb.push_back(output_json(c, mine));
        o.pushKV("coinbase", cb);
        UniValue txs{UniValue::VARR};
        for (const auto& tx : b->transactions) {
            if (txs.size() >= 1000) break;
            UniValue t{UniValue::VOBJ};
            t.pushKV("txid", bt::hex_encode(tx.txid()));
            t.pushKV("inputs", static_cast<uint64_t>(tx.inputs.size()));
            UniValue outs{UniValue::VARR};
            for (const Output& out : tx.outputs) outs.push_back(output_json(out, mine));
            t.pushKV("outputs", outs);
            txs.push_back(t);
        }
        o.pushKV("transactions", txs);
        return o;
    }

    UniValue tx_detail(const Hash32& txid, const Mine& mine)
    {
        auto t{node.transaction(txid)};
        UniValue o{UniValue::VOBJ};
        o.pushKV("txid", bt::hex_encode(txid));
        if (!t) {
            // Waiting in the mempool?
            auto [txs, fees] = node.mempool_transactions(1000);
            (void)fees;
            for (auto& [atx, spent] : txs) {
                if (atx.transaction.txid() != txid) continue;
                o.pushKV("pending", true);
                UniValue ins{UniValue::VARR};
                uint64_t in_total{0}, out_total{0};
                for (const FilledOutput& s : spent) {
                    ins.push_back(output_json(s, mine));
                    in_total += s.get_value();
                }
                UniValue outs{UniValue::VARR};
                for (const Output& out : atx.transaction.outputs) {
                    outs.push_back(output_json(out, mine));
                    out_total += out.get_value();
                }
                o.pushKV("inputs", ins);
                o.pushKV("outputs", outs);
                if (in_total >= out_total) o.pushKV("fee", n64(in_total - out_total));
                return o;
            }
            throw HostError("No such transaction");
        }
        o.pushKV("pending", false);
        if (auto blk{block_of_tx(txid)}) {
            o.pushKV("block", bt::hex_encode(*blk));
            if (auto b{block_of(*blk)}) {
                o.pushKV("height", static_cast<uint64_t>(b->first));
                if (auto tm{main_time(b->second)}) o.pushKV("time", *tm);
                if (auto h{node.height()}) o.pushKV("confirmations", static_cast<uint64_t>(*h >= b->first ? *h - b->first + 1 : 0));
            }
        }
        UniValue ins{UniValue::VARR};
        for (const OutPoint& op : t->inputs) {
            UniValue i{UniValue::VOBJ};
            i.pushKV("outpoint", json::outpoint(op));
            ins.push_back(i);
        }
        UniValue outs{UniValue::VARR};
        for (const Output& out : t->outputs) outs.push_back(output_json(out, mine));
        if (!t->memo.empty()) o.pushKV("memo", bt::hex_encode(t->memo));
        o.pushKV("inputs", ins);
        o.pushKV("outputs", outs);
        return o;
    }

    UniValue address_detail(const Address& a, const Mine& mine)
    {
        const std::set<Address> one{a};
        uint64_t balance{0};
        UniValue utxos{UniValue::VARR};
        for (auto& [op, o] : node.utxos_by_addresses(one)) {
            balance += o.get_value();
            if (utxos.size() < 500) {
                UniValue u{output_json(o, mine)};
                u.pushKV("outpoint", json::outpoint(op));
                utxos.push_back(u);
            }
        }
        UniValue stxos{UniValue::VARR};
        for (auto& [op, s] : node.stxos_by_addresses(one)) {
            if (stxos.size() >= 500) break;
            UniValue u{output_json(s.output, mine)};
            u.pushKV("outpoint", json::outpoint(op));
            u.pushKV("spentBy", s.inpoint.kind == InPoint::Withdrawal ? "bundle:" + bt::hex_encode_rev(s.inpoint.id.span()) : bt::hex_encode(s.inpoint.id));
            stxos.push_back(u);
        }
        UniValue o{UniValue::VOBJ};
        o.pushKV("address", a.to_base58());
        if (mine) o.pushKV("mine", mine->contains(a));
        o.pushKV("balance", n64(balance));
        o.pushKV("utxos", utxos);
        o.pushKV("spent", stxos);
        o.pushKV("depositAddress", a.format_for_deposit());
        return o;
    }

    // ---------------------------------------------------------- peg
    UniValue peg()
    {
        const auto mine{addresses()};
        UniValue o{UniValue::VOBJ};
        auto pending{node.pending_withdrawal_bundle()};
        std::set<OutPoint> in_pending;
        if (pending) {
            UniValue p{UniValue::VOBJ};
            p.pushKV("m6id", bt::hex_encode_rev(pending->m6id().span()));
            uint64_t total{0};
            for (auto& [op, out] : pending->spend_utxos) {
                total += out.get_value();
                in_pending.insert(op);
            }
            p.pushKV("withdrawals", static_cast<uint64_t>(pending->spend_utxos.size()));
            p.pushKV("total", n64(total));
            o.pushKV("pendingBundle", p);
        } else {
            o.pushKV("pendingBundle", UniValue{});
        }
        auto failed{node.latest_failed_withdrawal_bundle_height()};
        o.pushKV("lastFailedHeight", failed ? UniValue(uint64_t(*failed)) : UniValue{});
        UniValue w{UniValue::VARR};
        auto withdrawal = [&](const OutPoint& op, const FilledOutput& out, const std::string& state, const std::optional<Hash32>& m6id) {
            UniValue r{UniValue::VOBJ};
            r.pushKV("outpoint", json::outpoint(op));
            r.pushKV("txid", bt::hex_encode(op.txid));
            r.pushKV("mainAddress", out.content.main_address.to_string());
            r.pushKV("amount", n64(out.content.value));
            r.pushKV("mainFee", n64(out.content.main_fee));
            r.pushKV("state", state);
            if (m6id) {
                r.pushKV("m6id", bt::hex_encode_rev(m6id->span()));
                if (auto b{bundle_status(*m6id)}) r.pushKV("bundleStatus", to_string(b->second));
            }
            w.push_back(r);
        };
        for (auto& [op, out] : node.utxos_by_addresses(mine)) {
            if (!out.content.is_withdrawal()) continue;
            withdrawal(op, out, in_pending.contains(op) ? "in-pending-bundle" : "waiting", pending && in_pending.contains(op) ? std::optional<Hash32>{pending->m6id()} : std::nullopt);
        }
        for (auto& [op, s] : node.stxos_by_addresses(mine)) {
            if (!s.output.content.is_withdrawal() || s.inpoint.kind != InPoint::Withdrawal) continue;
            auto b{bundle_status(s.inpoint.id)};
            std::string state{"submitted"};
            if (b && b->second == BundleStatus::Confirmed) state = "paid";
            else if (b && b->second == BundleStatus::Failed) state = "failed";
            withdrawal(op, s.output, state, s.inpoint.id);
        }
        o.pushKV("withdrawals", w);
        o.pushKV("wealth", n64(node.sidechain_wealth()));
        o.pushKV("mainchain", link ? link->info() : UniValue{});
        o.pushKV("slot", static_cast<int>(THIS_SIDECHAIN));
        return o;
    }

    // ---------------------------------------------------------- questions of the spends
    Address side_address(const UniValue& v, const std::string& what)
    {
        if (!v.isStr()) throw HostError(bt::appui::HOST_INVALID_REQUEST, what + ": a BitNames address");
        auto a{Address::from_base58(v.get_str())};
        if (!a) throw HostError(bt::appui::HOST_INVALID_REQUEST, what + ": not a BitNames address (" + v.get_str() + ")");
        return *a;
    }

    bt::btc::Address main_address(const UniValue& v)
    {
        if (!v.isStr()) throw HostError(bt::appui::HOST_INVALID_REQUEST, "mainchain_address: an eCash address");
        auto a{bt::btc::Address::parse(v.get_str())};
        if (!a) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Not an eCash address: " + v.get_str());
        if (!main_address_of_network(*a, network)) throw HostError(bt::appui::HOST_INVALID_REQUEST, "This eCash address is of another network than the one this node follows (" + network + ")");
        return *a;
    }

    uint64_t available()
    {
        return balances(addresses()).available;
    }

    void enough(uint64_t need)
    {
        const uint64_t have{available()};
        if (need > have) throw HostError(bt::appui::RPC_WALLET_ERROR, "Not enough available: " + coins(have) + " for " + coins(need));
    }

    static UniValue same_numbers(const UniValue& p, size_t n, const std::vector<size_t>& numbers)
    {
        if (!p.isArray() || p.size() < n) throw HostError(bt::appui::HOST_INVALID_REQUEST, "params: " + std::to_string(n) + " parameters");
        UniValue out{UniValue::VARR};
        for (size_t i{0}; i < p.size() && i < n; ++i) {
            if (std::find(numbers.begin(), numbers.end(), i) != numbers.end()) out.push_back(n64(u64_of(p[i], "param " + std::to_string(i))));
            else out.push_back(p[i]);
        }
        return out;
    }

    std::map<std::string, Confirmed> confirmed()
    {
        std::map<std::string, Confirmed> c;
        c["create_transfer"] = Confirmed{
            [](const UniValue& p) {
                // [dest, value, fee] and, on BitNames, an optional memo (hex) kept as it is.
                UniValue out{same_numbers(p, 3, {1, 2})};
                if (p.size() > 3 && !p[3].isNull()) {
                    if (!p[3].isStr() || !bt::hex_decode(p[3].get_str())) throw HostError(bt::appui::HOST_INVALID_REQUEST, "memo: hex");
                    out.push_back(p[3]);
                }
                return out;
            },
            [this](const UniValue& p) {
                const Address to{side_address(p[0], "dest")};
                const uint64_t value{p[1].getInt<uint64_t>()}, fee{p[2].getInt<uint64_t>()};
                if (value == 0) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Nothing to send");
                if (value + fee < value) throw HostError(bt::appui::HOST_INVALID_REQUEST, "amount overflow");
                enough(value + fee);
                Question q;
                q.title = "Send " + coins(value);
                q.message = addresses().contains(to) ? "To an address of this wallet." : "To this address on BitNames. A payment cannot be taken back.";
                q.accept = "Send";
                q.kind = "send";
                q.rows = {{"To", to.to_base58(), "address"}, {"Amount", coins(value), "amount"}, {"Fee", coins(fee), "amount"}, {"Total", coins(value + fee), "total"}};
                if (p.size() > 3) q.rows.push_back({"Memo (hex, visible on the chain)", p[3].get_str(), "text"});
                return q;
            },
            [this](const UniValue& p) { return l2l_call("create_transfer", p); }};
        c["reserve_bitname"] = Confirmed{
            [](const UniValue& p) {
                if (!p.isArray() || p.size() < 1 || !p[0].isStr()) throw HostError(bt::appui::HOST_INVALID_REQUEST, "params: [plain_name]");
                UniValue out{UniValue::VARR};
                out.push_back(p[0]);
                return out;
            },
            [this](const UniValue& p) {
                const std::string name{p[0].get_str()};
                if (name.empty() || name.size() > 255) throw HostError(bt::appui::HOST_INVALID_REQUEST, "A name of 1 to 255 characters");
                if (node.bitname_current(name_hash(name))) throw HostError(bt::appui::HOST_INVALID_REQUEST, "This name is registered already");
                // Their wallet reserves without an input when it has no coin, a reservation anyone can replay: ours asks
                // for a coin first (spent back to the wallet, no fee).
                if (available() == 0) throw HostError(bt::appui::RPC_WALLET_ERROR, "A reservation spends one of your coins back to you: get some BitNames coins first");
                Question q;
                q.title = "Reserve the name " + name;
                q.message = "A reservation hides the name until you register it: only its commitment goes on the chain now. Register it once the "
                            "reservation is in a block (the next step of this page).";
                q.accept = "Reserve";
                q.kind = "name.reserve";
                q.rows = {{"Name", name, "text"}, {"Its id (hash)", bt::hex_encode(name_hash(name)), "text"}};
                return q;
            },
            [this](const UniValue& p) { return l2l_call("reserve_bitname", p); }};
        c["register_bitname"] = Confirmed{
            [](const UniValue& p) {
                if (!p.isArray() || p.size() < 1 || !p[0].isStr()) throw HostError(bt::appui::HOST_INVALID_REQUEST, "params: [plain_name, bitname_data?]");
                UniValue out{UniValue::VARR};
                out.push_back(p[0]);
                if (p.size() > 1 && !p[1].isNull()) {
                    if (!p[1].isObject()) throw HostError(bt::appui::HOST_INVALID_REQUEST, "bitname_data: an object");
                    out.push_back(p[1]);
                }
                return out;
            },
            [this](const UniValue& p) {
                const std::string name{p[0].get_str()};
                if (node.bitname_current(name_hash(name))) throw HostError(bt::appui::HOST_INVALID_REQUEST, "This name is registered already");
                Question q;
                q.title = "Register the name " + name;
                q.message = "Reveals the name and makes it yours, with these records. Anyone can look it up.";
                q.accept = "Register";
                q.kind = "name.register";
                q.rows = {{"Name", name, "text"}};
                if (p.size() > 1) {
                    MutableBitNameData d;
                    try {
                        d = json::parse_mutable_data(p[1]);
                    } catch (const std::exception& e) {
                        throw HostError(bt::appui::HOST_INVALID_REQUEST, std::string{"bitname_data: "} + e.what());
                    }
                    // Each record as the node parsed it (what it will write), under its words.
                    static const std::map<std::string, std::string> labels{
                        {"commitment", "Commitment"}, {"socket_addr_v4", "IPv4 address"}, {"socket_addr_v6", "IPv6 address"},
                        {"encryption_pubkey", "Encryption key"}, {"signing_pubkey", "Signing key"}, {"paymail_fee_sats", "Paymail fee (sat)"}};
                    const UniValue j{json::mutable_data(d)};
                    for (size_t i{0}; i < j.size(); ++i) {
                        const UniValue& v{j.getValues()[i]};
                        if (v.isNull()) continue;
                        std::string text{v.isStr() ? v.get_str() : v.write()};
                        if (j.getKeys()[i] == "commitment" && d.commitment) text = bt::hex_encode(*d.commitment);
                        const auto l{labels.find(j.getKeys()[i])};
                        q.rows.push_back({l != labels.end() ? l->second : j.getKeys()[i], text, "text"});
                    }
                }
                return q;
            },
            [this](const UniValue& p) { return l2l_call("register_bitname", p); }};
        c["create_transfer_many"] = Confirmed{
            [](const UniValue& p) {
                if (!p.isArray() || p.size() < 2 || !p[0].isObject()) throw HostError(bt::appui::HOST_INVALID_REQUEST, "params: {address: satoshis}, fee");
                UniValue dests{UniValue::VOBJ};
                for (size_t i{0}; i < p[0].size(); ++i) dests.pushKV(p[0].getKeys()[i], n64(u64_of(p[0].getValues()[i], "amount")));
                UniValue out{UniValue::VARR};
                out.push_back(dests);
                out.push_back(n64(u64_of(p[1], "fee_sats")));
                return out;
            },
            [this](const UniValue& p) {
                const UniValue& dests{p[0]};
                if (dests.size() == 0) throw HostError(bt::appui::HOST_INVALID_REQUEST, "No recipient");
                if (dests.size() > 2000) throw HostError(bt::appui::HOST_INVALID_REQUEST, "At most 2000 recipients in one payment");
                const uint64_t fee{p[1].getInt<uint64_t>()};
                uint64_t total{fee};
                Question q;
                q.kind = "send-many";
                q.accept = "Send";
                std::set<Address> seen;
                for (size_t i{0}; i < dests.size(); ++i) {
                    const Address a{side_address(UniValue{dests.getKeys()[i]}, "dest")};
                    if (!seen.insert(a).second) throw HostError(bt::appui::HOST_INVALID_REQUEST, "invalid entry: found duplicate key");
                    const uint64_t v{dests.getValues()[i].getInt<uint64_t>()};
                    if (total + v < total) throw HostError(bt::appui::HOST_INVALID_REQUEST, "amount overflow");
                    total += v;
                    q.rows.push_back({"To", a.to_base58(), "address"});
                    q.rows.push_back({"Amount", coins(v), "amount"});
                }
                enough(total);
                q.title = "Send " + coins(total - fee) + " to " + std::to_string(dests.size()) + (dests.size() == 1 ? " recipient" : " recipients");
                q.message = "One transaction on BitNames. A payment cannot be taken back.";
                q.rows.push_back({"Fee", coins(fee), "amount"});
                q.rows.push_back({"Total", coins(total), "total"});
                return q;
            },
            [this](const UniValue& p) { return l2l_call("create_transfer_many", p); }};
        c["create_withdrawal"] = Confirmed{
            [](const UniValue& p) { return same_numbers(p, 4, {1, 2, 3}); },
            [this](const UniValue& p) {
                const bt::btc::Address to{main_address(p[0])};
                const uint64_t value{p[1].getInt<uint64_t>()}, fee{p[2].getInt<uint64_t>()}, main_fee{p[3].getInt<uint64_t>()};
                if (value == 0) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Nothing to withdraw");
                const uint64_t total{value + fee + main_fee};
                if (total < value) throw HostError(bt::appui::HOST_INVALID_REQUEST, "amount overflow");
                enough(total);
                Question q;
                q.title = "Withdraw " + coins(value) + " to eCash";
                q.message = "Your coins leave BitNames now. eCash pays them to the address below once a withdrawal bundle with them is "
                            "accepted by eCash's miners, which takes a long time (their votes). Until then they show as being withdrawn.";
                q.accept = "Withdraw";
                q.kind = "withdraw";
                q.rows = {{"To (on eCash)", to.to_string(), "address"}, {"Amount", coins(value), "amount"}, {"Fee on eCash", coins(main_fee), "amount"},
                          {"Fee on BitNames", coins(fee), "amount"}, {"Total", coins(total), "total"}};
                return q;
            },
            [this](const UniValue& p) { return l2l_call("create_withdrawal", p); }};
        c["create_deposit"] = Confirmed{
            [](const UniValue& p) { return same_numbers(p, 3, {1, 2}); },
            [this](const UniValue& p) {
                const Address to{side_address(p[0], "address")};
                const uint64_t value{p[1].getInt<uint64_t>()}, fee{p[2].getInt<uint64_t>()};
                if (value == 0) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Nothing to deposit");
                const bool ours{addresses().contains(to)};
                Question q;
                q.title = "Deposit " + coins(value) + " into BitNames";
                q.message = "Paid on eCash by the wallet of the mainchain interface this node uses (" + node.enforcer().url() +
                            "), into BitNames' slot " + std::to_string(int(THIS_SIDECHAIN)) + ". It is credited on BitNames in the first block after eCash mines it.";
                if (!ours) {
                    q.message += " The address is NOT one of this wallet: the coins go to whoever holds it.";
                    q.level = "danger";
                }
                q.accept = "Deposit";
                q.kind = "deposit";
                q.rows = {{"Into (BitNames)", to.to_base58(), "address"}, {"Amount", coins(value), "amount"}, {"Fee on eCash", coins(fee), "amount"},
                          {"Total (paid on eCash)", coins(value + fee), "total"}};
                return q;
            },
            [this](const UniValue& p) {
                UniValue r{l2l_call("create_deposit", p)};
                if (poller) poller->poke();
                return r;
            }};
        c["mine"] = Confirmed{
            [](const UniValue& p) {
                UniValue out{UniValue::VARR};
                if (p.isArray() && p.size() > 0 && !p[0].isNull()) out.push_back(n64(u64_of(p[0], "fee")));
                return out;
            },
            [this](const UniValue& p) {
                const uint64_t bid{p.size() > 0 ? p[0].getInt<uint64_t>() : App::EMPTY_BLOCK_BMM_BRIBE};
                Question q;
                q.title = "Merge-mine a block of BitNames";
                q.message = "Asks eCash's miners to include the next block of BitNames (blind merged mining), with a bid paid on eCash by the "
                            "wallet of the mainchain interface (" + node.enforcer().url() + "). The bid is paid whether or not the block is taken.";
                q.accept = "Bid";
                q.kind = "mine";
                q.rows = {{"Bid (at most)", p.size() > 0 ? coins(bid) : "the block's fees, or " + coins(App::EMPTY_BLOCK_BMM_BRIBE), "amount"}};
                return q;
            },
            [this](const UniValue& p) { return l2l_call("mine", p); }};
        // Every spend's balance looked at again at once.
        for (auto& [name, conf] : c) {
            auto run{conf.run};
            conf.run = [this, run](const UniValue& p) {
                UniValue r{run(p)};
                if (poller) poller->poke();
                return r;
            };
        }
        return c;
    }
};

const std::vector<std::string>& AppLayer::l2l_reads()
{
    static const std::vector<std::string> reads{"balance", "bitname_data", "bitnames", "format_deposit_address", "get_best_mainchain_block_hash", "get_best_sidechain_block_hash",
                                                "get_block", "get_block_hash", "get_bmm_inclusions", "get_paymail", "get_stxos", "get_transaction", "get_transaction_info",
                                                "get_utxos", "get_wallet_addresses", "get_wallet_utxos", "getblockcount", "latest_failed_withdrawal_bundle_height", "list_mempool",
                                                "list_peers", "list_stxos", "list_utxos", "mainchain_sync_progress", "my_utxos", "openapi_schema", "pending_withdrawal_bundle",
                                                "sidechain_wealth"};
    return reads;
}

AppLayer::AppLayer(App& app, std::string network, std::string datadir, bt::appui::AppOptions options)
    : m_(std::make_unique<Impl>(app, std::move(network), std::move(datadir), std::move(options)))
{
}

AppLayer::~AppLayer() { stop(); }

uint16_t AppLayer::port() const { return server_ ? server_->port() : 0; }

UniValue AppLayer::history(size_t limit) { return m_->history(limit); }

bool AppLayer::start(std::string& err)
{
    Impl& m{*m_};
    if (!bt::fsperm::private_dir(m.datadir)) {
        err = "cannot make " + m.datadir;
        return false;
    }
    m.store = std::make_unique<bt::appui::AppStore>(m.datadir + "/backbone-app.sqlite");
    std::string why;
    bt::appui::ServerOptions so{bt::appui::server_options(m.options, m.datadir, why)};
    if (!why.empty()) {
        err = why;
        return false;
    }
    server_ = std::make_unique<bt::appui::RpcServer>(std::move(so));
    m.link = std::make_unique<bt::appui::LinkMonitor>(m.node.enforcer(), THIS_SIDECHAIN, [&m] { return m.followed(); });

    // ---- the app RPC's own methods: the LayerTwo reads, as theirs; the reads of the kit's shell; the setup of the wallet.
    for (const std::string& name : l2l_reads()) {
        server_->add(name, {}, [&m, name](const bt::appui::Call& c) { return m.l2l_call(name, c.params); });
    }
    server_->add("getmainchaininfo", {}, [&m](const bt::appui::Call&) { return m.link->info(); });
    server_->add("getbalances", {}, [&m](const bt::appui::Call&) {
        UniValue mine{UniValue::VOBJ};
        Impl::Balances b;
        if (m.wallet.has_seed()) b = m.balances(m.addresses());
        mine.pushKV("trusted", bt::appui::coins_value(b.available));
        mine.pushKV("untrusted_pending", bt::appui::coins_value(b.pending_in));
        mine.pushKV("immature", bt::appui::coins_value(b.withdrawing));
        UniValue out{UniValue::VOBJ};
        out.pushKV("mine", mine);
        return out;
    });
    server_->add("getblockchaininfo", {}, [&m](const bt::appui::Call&) {
        UniValue o{UniValue::VOBJ};
        auto h{m.node.height()};
        auto t{m.node.tip()};
        o.pushKV("chain", m.network);
        o.pushKV("blocks", h ? int64_t(*h) : int64_t{-1});
        o.pushKV("headers", h ? int64_t(*h) : int64_t{-1});
        o.pushKV("bestblockhash", t ? bt::hex_encode(*t) : "");
        o.pushKV("initialblockdownload", false);
        o.pushKV("verificationprogress", 1.0);
        o.pushKV("warnings", UniValue{UniValue::VARR});
        return o;
    });
    server_->add("getnetworkinfo", {}, [&m](const bt::appui::Call&) {
        UniValue o{UniValue::VOBJ};
        size_t n{0};
        for (auto& p : m.node.peers()) n += p.connected ? 1 : 0;
        o.pushKV("version", 1800200);
        o.pushKV("subversion", std::string{"/backbone-bitnames:"} + VERSION_TEXT + "/");
        o.pushKV("connections", static_cast<uint64_t>(n));
        o.pushKV("networkactive", true);
        o.pushKV("warnings", UniValue{UniValue::VARR});
        return o;
    });
    server_->add("uptime", {}, [&m](const bt::appui::Call&) {
        return UniValue(static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - m.started).count()));
    });
    // The setup of the wallet by the unified wallet (doc/app.md "One backup phrase"): its own user (the cookie) sets
    // the phrase it derived; refused when the wallet has another one. Never offered to the pages.
    server_->add("getwalletphraseinfo", {}, [&m](const bt::appui::Call&) { return m.seed_status(); });
    server_->add("setwalletphrase", {"phrase"}, [&m](const bt::appui::Call& c) {
        if (!c[0].isStr()) throw RpcError(bt::appui::RPC_INVALID_PARAMETER, "phrase: the 12 to 24 words");
        std::string phrase{c[0].get_str()};
        try {
            UniValue r{m.set_phrase(phrase, "unified")};
            sodium_memzero(phrase.data(), phrase.size());
            LOG_INFO("app layer: the wallet's phrase was set by the app (fingerprint %s)", r.find_value("fingerprint").get_str().c_str());
            return r;
        } catch (const HostError& e) {
            sodium_memzero(phrase.data(), phrase.size());
            throw RpcError(e.code, e.what());
        }
    });
    server_->add("stop", {}, [&m](const bt::appui::Call&) {
        if (m.app.on_stop) m.app.on_stop();
        return UniValue("BitNames stopping");
    });
    server_->add("getappmanifest", {}, [this](const bt::appui::Call&) { return manifest(); });

    // ---- the host of the pages
    bt::appui::ChainHost chain;
    chain.name = "BitNames";
    chain.stem = "bitnames";
    chain.network = m.network;
    chain.info = [&m] { return m.info(); };
    chain.wallet_id = [&m] { return m.wallet_id(); };
    chain.page_reads = {"getmainchaininfo", "getbalances", "getblockchaininfo", "getnetworkinfo", "uptime"};
    for (const std::string& r : l2l_reads()) chain.page_reads.insert(r);
    chain.confirmed = m.confirmed();
    auto& H{chain.host};
    auto& P{chain.privileges};
    H["dropin.overview"] = [&m](const UniValue&, HostEnv&) {
        UniValue o{UniValue::VOBJ};
        const bool has{m.wallet.has_seed()};
        Impl::Balances b;
        if (has) b = m.balances(m.addresses());
        UniValue w{UniValue::VOBJ};
        w.pushKV("hasSeed", has);
        w.pushKV("available", n64(b.available));
        w.pushKV("withdrawing", n64(b.withdrawing));
        w.pushKV("pendingIn", n64(b.pending_in));
        w.pushKV("pendingOut", n64(b.pending_out));
        o.pushKV("wallet", w);
        auto h{m.node.height()};
        auto t{m.node.tip()};
        UniValue c{UniValue::VOBJ};
        c.pushKV("height", h ? int64_t(*h) : int64_t{-1});
        c.pushKV("tip", t ? bt::hex_encode(*t) : "");
        size_t peers{0};
        for (auto& p : m.node.peers()) peers += p.connected ? 1 : 0;
        c.pushKV("peers", static_cast<uint64_t>(peers));
        c.pushKV("wealth", n64(m.node.sidechain_wealth()));
        c.pushKV("slot", static_cast<int>(THIS_SIDECHAIN));
        c.pushKV("network", m.network);
        o.pushKV("chain", c);
        o.pushKV("mainchain", m.link->info());
        return o;
    };
    P["dropin.overview"] = {"balance", "getblockcount"};
    H["dropin.history"] = [&m](const UniValue& p, HostEnv&) {
        const UniValue& lim{param(p, "limit")};
        const size_t limit{lim.isNum() ? static_cast<size_t>(std::clamp<int64_t>(lim.getInt<int64_t>(), 1, 5000)) : size_t{500}};
        if (!m.wallet.has_seed()) return UniValue{UniValue::VARR};
        return m.history(limit);
    };
    P["dropin.history"] = {"get_wallet_utxos"};
    H["dropin.newAddress"] = [&m](const UniValue&, HostEnv&) {
        if (!m.wallet.has_seed()) throw HostError(bt::appui::RPC_WALLET_ERROR, "The wallet has no backup phrase yet: set it up first");
        const Address a{m.wallet.get_new_address()};
        UniValue o{UniValue::VOBJ};
        o.pushKV("address", a.to_base58());
        o.pushKV("depositAddress", a.format_for_deposit());
        return o;
    };
    P["dropin.newAddress"] = {"get_new_address"};
    H["dropin.addresses"] = [&m](const UniValue&, HostEnv&) {
        UniValue out{UniValue::VARR};
        if (!m.wallet.has_seed()) return out;
        std::map<Address, std::pair<uint64_t, uint64_t>> got; // balance, received
        const auto mine{m.addresses()};
        for (auto& [op, o] : m.node.utxos_by_addresses(mine)) {
            got[o.address].first += o.get_value();
            got[o.address].second += o.get_value();
        }
        for (auto& [op, s] : m.node.stxos_by_addresses(mine)) got[s.output.address].second += s.output.get_value();
        for (const Address& a : m.wallet.addresses()) {
            UniValue r{UniValue::VOBJ};
            r.pushKV("address", a.to_base58());
            r.pushKV("depositAddress", a.format_for_deposit());
            r.pushKV("balance", n64(got[a].first));
            r.pushKV("received", n64(got[a].second));
            out.push_back(r);
        }
        return out;
    };
    P["dropin.addresses"] = {"get_wallet_addresses"};
    H["dropin.blocks"] = [&m](const UniValue& p, HostEnv&) {
        const UniValue& cnt{param(p, "count")};
        const UniValue& from{param(p, "from")};
        const int64_t count{cnt.isNum() ? std::clamp<int64_t>(cnt.getInt<int64_t>(), 1, 200) : int64_t{20}};
        UniValue out{UniValue::VARR};
        auto h{m.node.height()};
        if (!h) return out;
        int64_t at{from.isNum() ? std::min<int64_t>(from.getInt<int64_t>(), *h) : int64_t(*h)};
        for (; at >= 0 && static_cast<int64_t>(out.size()) < count; --at) {
            auto hash{m.node.block_hash_at(static_cast<uint32_t>(at))};
            if (!hash) break;
            auto hd{m.node.header(*hash)};
            auto b{m.node.body(*hash)};
            if (!hd || !b) continue;
            out.push_back(m.block_summary(static_cast<uint32_t>(at), *hash, *hd, *b));
        }
        return out;
    };
    P["dropin.blocks"] = {"get_block"};
    H["dropin.block"] = [&m](const UniValue& p, HostEnv& env) {
        const UniValue& height{param(p, "height")};
        if (height.isNum()) {
            auto hash{m.node.block_hash_at(static_cast<uint32_t>(std::clamp<int64_t>(height.getInt<int64_t>(), 0, UINT32_MAX)))};
            if (!hash) throw HostError("No block at this height");
            return m.block_detail(*hash, m.mine_for(env));
        }
        auto hash{m.parse_hash(str_param(p, "hash"))};
        if (!hash) throw HostError(bt::appui::HOST_INVALID_REQUEST, "hash: 64 hex digits");
        return m.block_detail(*hash, m.mine_for(env));
    };
    P["dropin.block"] = {"get_block"};
    H["dropin.transaction"] = [&m](const UniValue& p, HostEnv& env) {
        auto txid{m.parse_hash(str_param(p, "txid"))};
        if (!txid) throw HostError(bt::appui::HOST_INVALID_REQUEST, "txid: 64 hex digits");
        return m.tx_detail(*txid, m.mine_for(env));
    };
    P["dropin.transaction"] = {"get_transaction"};
    H["dropin.address"] = [&m](const UniValue& p, HostEnv& env) {
        auto a{Address::from_base58(str_param(p, "address"))};
        if (!a) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Not a BitNames address");
        return m.address_detail(*a, m.mine_for(env));
    };
    P["dropin.address"] = {"get_utxos", "get_stxos"};
    H["dropin.search"] = [&m](const UniValue& p, HostEnv&) {
        std::string q{str_param(p, "query")};
        q.erase(0, q.find_first_not_of(" \t"));
        q.erase(q.find_last_not_of(" \t") + 1);
        UniValue o{UniValue::VOBJ};
        if (q.size() > 120) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Too long");
        if (!q.empty() && q.size() <= 10 && q.find_first_not_of("0123456789") == std::string::npos) {
            auto hash{m.node.block_hash_at(static_cast<uint32_t>(std::min<uint64_t>(std::stoull(q), UINT32_MAX)))};
            if (hash) {
                o.pushKV("kind", "block");
                o.pushKV("hash", bt::hex_encode(*hash));
                return o;
            }
        } else if (auto h{m.parse_hash(q)}) {
            if (m.node.header(*h)) {
                o.pushKV("kind", "block");
                o.pushKV("hash", q);
                return o;
            }
            o.pushKV("kind", "transaction");
            o.pushKV("txid", q);
            return o;
        } else if (Address::from_base58(q)) {
            o.pushKV("kind", "address");
            o.pushKV("address", q);
            return o;
        } else if (q.rfind("s2_", 0) == 0) {
            // A deposit address: the BitNames address inside.
            const size_t end{q.rfind('_')};
            if (end > 3) {
                const std::string inner{q.substr(3, end - 3)};
                if (Address::from_base58(inner)) {
                    o.pushKV("kind", "address");
                    o.pushKV("address", inner);
                    return o;
                }
            }
        }
        o.pushKV("kind", "none");
        return o;
    };
    P["dropin.search"] = {"get_block", "get_transaction"};
    H["dropin.checkAddress"] = [&m](const UniValue& p, HostEnv& env) {
        const std::string text{str_param(p, "address")};
        const std::string side{param(p, "side").isStr() ? param(p, "side").get_str() : "bitnames"};
        UniValue o{UniValue::VOBJ};
        if (side == "mainchain") {
            auto a{bt::btc::Address::parse(text)};
            o.pushKV("valid", a.has_value() && main_address_of_network(*a, m.network));
            if (a && !main_address_of_network(*a, m.network)) o.pushKV("error", "an eCash address of another network");
            else if (!a) o.pushKV("error", Address::from_base58(text) ? "a BitNames address, not an eCash one" : "not an eCash address");
            return o;
        }
        auto a{Address::from_base58(text)};
        o.pushKV("valid", a.has_value());
        // Whether it is the wallet's: only to a caller that may read the wallet's addresses.
        if (a) {
            if (env.may_call(WALLET_READ)) o.pushKV("mine", m.addresses().contains(*a));
        } else {
            o.pushKV("error", bt::btc::Address::parse(text) ? "an eCash address, not a BitNames one" : text.rfind("s2_", 0) == 0 ? "a deposit address: use it on eCash" : "not a BitNames address");
        }
        return o;
    };
    P["dropin.checkAddress"] = {};
    H["dropin.peg"] = [&m](const UniValue&, HostEnv&) { return m.peg(); };
    P["dropin.peg"] = {"pending_withdrawal_bundle", "get_wallet_utxos"};
    H["dropin.peers"] = [&m](const UniValue&, HostEnv&) {
        UniValue out{UniValue::VARR};
        for (auto& pv : m.node.peers()) {
            UniValue o{UniValue::VOBJ};
            o.pushKV("address", pv.address.to_string());
            o.pushKV("connected", pv.connected);
            o.pushKV("inbound", pv.inbound);
            out.push_back(o);
        }
        return out;
    };
    P["dropin.peers"] = {"list_peers"};
    H["dropin.peers.connect"] = [&m](const UniValue& p, HostEnv&) {
        std::string a{str_param(p, "address")};
        if (a.rfind(':') == std::string::npos) a += ":" + std::to_string(DEFAULT_PORT);
        std::string err;
        if (!m.node.connect_peer(a, err)) throw HostError(err);
        return UniValue{true};
    };
    P["dropin.peers.connect"] = {"connect_peer"};
    H["dropin.peers.forget"] = [&m](const UniValue& p, HostEnv&) {
        std::string a{str_param(p, "address")};
        if (a.rfind(':') == std::string::npos) a += ":" + std::to_string(DEFAULT_PORT);
        return UniValue{m.node.forget_peer(a)};
    };
    P["dropin.peers.forget"] = {"forget_peer"};
    // ---- the backup phrase: its words shown only in the app's trusted dialog, never to the pages.
    H["dropin.seed.status"] = [&m](const UniValue&, HostEnv&) { return m.seed_status(); };
    P["dropin.seed.status"] = {"get_wallet_addresses"};
    H["dropin.seed.prepare"] = [&m](const UniValue&, HostEnv&) {
        if (m.wallet.has_seed()) throw HostError(bt::appui::RPC_WALLET_ERROR, "This wallet has a backup phrase already");
        UniValue o{UniValue::VOBJ};
        o.pushKV("id", m.phrases.put(bt::hd::generate_mnemonic(12)));
        o.pushKV("words", 12);
        return o;
    };
    P["dropin.seed.prepare"] = {"set_seed_from_mnemonic"};
    H["dropin.seed.create"] = [&m](const UniValue& p, HostEnv& env) {
        const std::string id{str_param(p, "id")};
        auto phrase{m.phrases.get(id)};
        if (!phrase) throw HostError(bt::appui::HOST_INVALID_REQUEST, "This new phrase is not known any more (5 minutes): make another");
        if (m.wallet.has_seed()) throw HostError(bt::appui::RPC_WALLET_ERROR, "This wallet has a backup phrase already");
        Question q;
        q.title = "Your backup phrase";
        q.message = "Write these 12 words down, in order, on paper, and keep them safe. They are the only way to get this wallet back. "
                    "Anyone who has them can take its coins. They are not shown to the app's pages.";
        q.details = Impl::words_block(*phrase);
        q.accept = "I wrote them down";
        q.level = "warning";
        q.kind = "phrase.create";
        if (!env.ask(q).accepted) throw HostError(bt::appui::HOST_CANCELLED, "Cancelled");
        UniValue r{m.set_phrase(*phrase, "app")};
        m.phrases.erase(id);
        return r;
    };
    P["dropin.seed.create"] = {"set_seed_from_mnemonic"};
    H["dropin.seed.restore"] = [&m](const UniValue& p, HostEnv& env) {
        std::string phrase{str_param(p, "phrase")};
        auto parsed{bt::hd::parse_mnemonic(phrase)};
        sodium_memzero(phrase.data(), phrase.size());
        if (!parsed) throw HostError(bt::appui::HOST_INVALID_REQUEST, bt::hd::mnemonic_error(str_param(p, "phrase")));
        if (m.wallet.has_seed()) throw HostError(bt::appui::RPC_WALLET_ERROR, "This wallet has a backup phrase already");
        auto seed{bt::hd::mnemonic_to_seed(*parsed)};
        const std::string fp{bt::appui::seed_fingerprint(seed.span())};
        sodium_memzero(seed.data(), seed.size());
        Question q;
        q.title = "Restore the wallet from this phrase";
        q.message = "The wallet takes the keys of this backup phrase. Its coins show once the node has looked at the chain.";
        q.rows = {{"Words", std::to_string(std::count(parsed->begin(), parsed->end(), ' ') + 1), "text"}, {"Fingerprint", fp, "text"}};
        q.accept = "Restore";
        q.kind = "phrase.restore";
        if (!env.ask(q).accepted) throw HostError(bt::appui::HOST_CANCELLED, "Cancelled");
        return m.set_phrase(*parsed, "restored");
    };
    P["dropin.seed.restore"] = {"set_seed_from_mnemonic"};
    // Shown or saved only when named in the whitelist (no privilege stands for it): the most sensitive read there is.
    H["dropin.seed.show"] = [&m](const UniValue&, HostEnv& env) {
        auto phrase{m.kept_phrase()};
        if (!phrase) throw HostError(bt::appui::RPC_WALLET_ERROR, "This wallet's phrase was not set through the app: keep the backup you made then");
        Question q;
        q.title = "Your backup phrase";
        q.message = "Make sure nobody can see your screen. Anyone who has these words can take this wallet's coins.";
        q.details = Impl::words_block(*phrase);
        q.accept = "Done";
        q.cancel = "Close";
        q.level = "warning";
        q.kind = "phrase.show";
        env.ask(q);
        sodium_memzero(phrase->data(), phrase->size());
        return UniValue{true};
    };
    H["dropin.seed.save"] = [&m](const UniValue& p, HostEnv& env) {
        const std::string path{str_param(p, "path")};
        const auto file{env.file(path, true)};
        auto phrase{m.kept_phrase()};
        if (!phrase) throw HostError(bt::appui::RPC_WALLET_ERROR, "This wallet's phrase was not set through the app: keep the backup you made then");
        Question q;
        q.title = "Save your backup phrase to a file";
        q.message = "Anyone who can read this file can take this wallet's coins. Keep it somewhere only you can reach, off this computer if you can.";
        q.rows = {{"File", path, "text"}};
        q.accept = "Save";
        q.kind = "phrase.save";
        if (!env.ask(q).accepted) throw HostError(bt::appui::HOST_CANCELLED, "Cancelled");
        try {
            bt::appui::ChosenFiles::write(file, "BitNames backup phrase (BIP-39, plain_bitnames keys)\n" + *phrase + "\n");
        } catch (const std::runtime_error& e) {
            sodium_memzero(phrase->data(), phrase->size());
            throw HostError(std::string{"The file chosen cannot be written: "} + e.what());
        }
        sodium_memzero(phrase->data(), phrase->size());
        return UniValue{true};
    };
    // ---- BitNames' own: the wallet's names, a name looked up, the directory of every name.
    H["bitnames.names"] = [&m](const UniValue&, HostEnv&) {
        // Owned names; reservations; and of those, the ones in a block whose name nobody registered yet (pending:
        // registering it is the wallet's next step), or whose registration waits in the mempool (registering).
        UniValue owned{UniValue::VARR}, reserved{UniValue::VARR}, pending{UniValue::VARR}, registering{UniValue::VARR};
        if (m.wallet.has_seed()) {
            std::set<OutPoint> spending;
            for (const AuthorizedTransaction& atx : m.node.mempool()) spending.insert(atx.transaction.inputs.begin(), atx.transaction.inputs.end());
            for (auto& [op, out] : m.wallet.utxos()) {
                if (out.content.is_bitname()) {
                    UniValue n{UniValue::VOBJ};
                    n.pushKV("hash", bt::hex_encode(out.content.bitname));
                    if (auto plain{m.wallet.plain_name(out.content.bitname)}) n.pushKV("name", *plain);
                    n.pushKV("address", out.address.to_base58());
                    if (auto d{m.node.bitname_current(out.content.bitname)}) n.pushKV("data", json::bitname_data(*d));
                    owned.push_back(n);
                } else if (out.content.is_reservation()) {
                    UniValue r{UniValue::VOBJ};
                    r.pushKV("txid", bt::hex_encode(out.content.reservation_txid));
                    r.pushKV("commitment", bt::hex_encode(out.content.reservation_commitment));
                    r.pushKV("address", out.address.to_base58());
                    reserved.push_back(r);
                    auto plain{m.wallet.reserved_name(out.content.reservation_commitment)};
                    if (!plain || m.node.bitname_current(name_hash(*plain))) continue;
                    UniValue n{UniValue::VOBJ};
                    n.pushKV("name", *plain);
                    n.pushKV("hash", bt::hex_encode(name_hash(*plain)));
                    (spending.contains(op) ? registering : pending).push_back(n);
                }
            }
        }
        UniValue o{UniValue::VOBJ};
        o.pushKV("owned", owned);
        o.pushKV("reservations", reserved);
        o.pushKV("pending", pending);
        o.pushKV("registering", registering);
        return o;
    };
    P["bitnames.names"] = {"get_wallet_utxos", "bitnames"};
    H["bitnames.resolve"] = [&m](const UniValue& p, HostEnv&) {
        std::string name{str_param(p, "name")};
        if (name.empty() || name.size() > 255) throw HostError(bt::appui::HOST_INVALID_REQUEST, "name: 1 to 255 characters");
        UniValue o{UniValue::VOBJ};
        const Hash32 h{name_hash(name)};
        o.pushKV("name", name);
        o.pushKV("hash", bt::hex_encode(h));
        auto d{m.node.bitname_current(h)};
        o.pushKV("registered", d.has_value());
        if (d) o.pushKV("data", json::bitname_data(*d));
        return o;
    };
    P["bitnames.resolve"] = {"bitname_data"};
    H["bitnames.directory"] = [&m](const UniValue& p, HostEnv& env) {
        const UniValue& lim{param(p, "limit")};
        const size_t limit{lim.isNum() ? static_cast<size_t>(std::clamp<int64_t>(lim.getInt<int64_t>(), 1, 5000)) : size_t{1000}};
        UniValue out{UniValue::VARR};
        // Its own names in words to a reader of the wallet; every other name by its hash (the chain keeps no words).
        const bool reader{env.may_call(WALLET_READ)};
        for (auto& [h, d] : m.node.bitnames()) {
            if (out.size() >= limit) break;
            UniValue n{UniValue::VOBJ};
            n.pushKV("hash", bt::hex_encode(h));
            if (reader) {
                if (auto plain{m.wallet.plain_name(h)}) n.pushKV("name", *plain);
            }
            n.pushKV("data", json::bitname_data(d));
            out.push_back(n);
        }
        return out;
    };
    P["bitnames.directory"] = {"bitnames"};

    chain.snapshot = [&m] { return m.poller ? m.poller->snapshot() : UniValue{UniValue::VOBJ}; };
    host_ = std::make_unique<bt::appui::RemoteHost>(std::move(chain), bt::appui::HostOptions{m.options.chooser, m.options.file_dir}, *server_);
    m.poller = std::make_unique<bt::appui::Poller>(host_->events(), WALLET_NAME, [&m] { return m.look(); });
    if (!server_->listen(err)) return false;
    m.link->start();
    m.poller->start();
    LOG_INFO("app RPC on 127.0.0.1:%u (%zu methods; the LayerTwo RPC is not changed by it)", unsigned(server_->port()), server_->methods().size());
    return true;
}

void AppLayer::stop()
{
    if (!m_) return;
    if (m_->poller) m_->poller->stop();
    if (m_->link) m_->link->stop();
    if (host_) host_->stop();
    if (server_) server_->stop();
}

std::vector<std::string> AppLayer::app_methods() const
{
    std::vector<std::string> out{server_ ? server_->methods() : std::vector<std::string>{}};
    return out;
}

UniValue AppLayer::manifest() const
{
    // What a pack of BitNames' pages uses of this node (the unified wallet names it in the app's whitelist): the
    // reads of the pages, the confirmed methods, the host methods, and the host's own methods.
    UniValue o{UniValue::VOBJ};
    o.pushKV("stem", "bitnames");
    o.pushKV("hostApi", bt::appui::HOST_API);
    UniValue reads{UniValue::VARR};
    for (const char* r : {"getmainchaininfo", "getbalances", "getblockchaininfo", "getnetworkinfo", "uptime"}) reads.push_back(r);
    for (const std::string& r : l2l_reads()) reads.push_back(r);
    o.pushKV("reads", reads);
    UniValue confirmed{UniValue::VARR};
    for (const char* c : {"create_deposit", "create_transfer", "create_transfer_many", "create_withdrawal", "mine", "register_bitname", "reserve_bitname"}) confirmed.push_back(c);
    o.pushKV("confirmed", confirmed);
    UniValue host{UniValue::VARR};
    for (const char* h : {"dropin.overview", "dropin.history", "dropin.newAddress", "dropin.addresses", "dropin.blocks", "dropin.block", "dropin.transaction",
                          "dropin.address", "dropin.search", "dropin.checkAddress", "dropin.peg", "dropin.peers", "dropin.peers.connect", "dropin.peers.forget",
                          "dropin.seed.status", "dropin.seed.prepare", "dropin.seed.create", "dropin.seed.restore", "dropin.seed.show", "dropin.seed.save",
                          "bitnames.names", "bitnames.resolve", "bitnames.directory"})
        host.push_back(h);
    o.pushKV("host", host);
    UniValue protocol{UniValue::VARR};
    for (const char* p : {"webuihost", "describeconfirmation", "webuievents", "webuichosenfile"}) protocol.push_back(p);
    o.pushKV("protocol", protocol);
    return o;
}

} // namespace bitnames
