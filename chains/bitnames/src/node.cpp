// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <bitnames/node.h>

#include <bt/fsperm.h>
#include <bt/log.h>
#include <bt/parse.h>

#include <algorithm>
#include <chrono>
#include <filesystem>

namespace bitnames {

using bt::kv::Txn;
using bt::mainchain::TwoWayPegData;
using bt::sidechain::PeerState;
using bt::sidechain::TipInfo;

static int64_t now_s()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

static constexpr uint8_t T_PEERS = 80;      // known peers (host:port)
static constexpr uint8_t T_MAIN_STAGE = 81; // ancestor sync staging (height BE -> info)
static constexpr uint8_t T_MAIN_TIP = 82;   // last mainchain tip we synced to

Node::Node(NodeConfig cfg) : cfg_(std::move(cfg)) {}

Node::~Node() { stop(); }

bool Node::start(std::string& err)
{
    if (!bt::fsperm::private_dir(cfg_.datadir)) {
        err = "cannot create " + cfg_.datadir;
        return false;
    }
    try {
        store_ = bt::kv::open_sqlite(cfg_.datadir + "/backbone-bitnames.sqlite");
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
    if (cfg_.rebuild_side_tips) {
        Txn t(*store_);
        side_tips_.clear(t);
        t.commit();
        LOG_INFO("side tips cleared; rebuilt from the mainchain at the first sync");
    }
    enforcer_ = std::make_unique<bt::enforcer::Client>(cfg_.mainchain_grpc_url, THIS_SIDECHAIN);
    magic_ = cfg_.magic_override ? *cfg_.magic_override : magic_bytes(cfg_.network);
    if (cfg_.zmq_addr) {
        zmq_ = std::make_unique<bt::zmq::Publisher>();
        if (!zmq_->bind(cfg_.zmq_addr->ip, cfg_.zmq_addr->port, err)) return false;
        LOG_INFO("ZMQ publisher on tcp://%s", cfg_.zmq_addr->to_string().c_str());
    }
    refresh_cache();
    running_ = true;
    main_thread_ = std::thread([this] { mainchain_loop(); });
    if (cfg_.p2p) {
        bt::quic::Callbacks cb;
        cb.on_connected = [this](bt::quic::ConnId c, const bt::quic::SockAddr& a, bool inbound) {
            std::lock_guard<std::mutex> l(peers_mu_);
            auto& p = peers_[c];
            p.conn = c;
            p.addr = a;
            p.inbound = inbound;
            p.connected = true;
            LOG_INFO("peer %s connected (%s)", a.to_string().c_str(), inbound ? "inbound" : "outbound");
        };
        // never take the node lock on the QUIC I/O thread
        cb.on_request = [this](bt::quic::ConnId c, int64_t s, Bytes p) { post_serve([this, c, s, p = std::move(p)]() mutable { on_request(c, s, std::move(p)); }); };
        cb.on_closed = [this](bt::quic::ConnId c, const std::string& why) {
            std::lock_guard<std::mutex> l(peers_mu_);
            auto it = peers_.find(c);
            if (it != peers_.end()) {
                LOG_INFO("peer %s disconnected: %s", it->second.addr.to_string().c_str(), why.c_str());
                if (!it->second.dial.empty()) dial_targets_[it->second.dial] = now_s() + 10;
                peers_.erase(it);
            }
        };
        bt::quic::Options opt;
        opt.server_names = cfg_.server_names;
        opt.max_request_bytes = bt::sidechain::READ_REQUEST_LIMIT;
        ep_ = std::make_unique<bt::quic::Endpoint>(cb, opt);
        if (!ep_->start(cfg_.net_addr, err)) return false;
        LOG_INFO("P2P listening on %s (magic %s)", ep_->local_address().to_string().c_str(), bt::hex_encode(ByteSpan(magic_.data(), 4)).c_str());
        if (cfg_.use_seeds)
            for (auto& s : seed_peers(cfg_.network)) dial_targets_[s] = 0;
        for (auto& p : cfg_.add_peers)
            if (bt::split_hostport(p, DEFAULT_PORT)) dial_targets_[p] = 0;
            else LOG_WARN("ignoring invalid --add-peer '%s'", p.c_str());
        {
            Txn t(*store_);
            t.scan(T_PEERS, [&](ByteSpan k, ByteSpan) {
                std::string hp(k.begin(), k.end());
                if (bt::split_hostport(hp)) dial_targets_[hp] = 0;
                return true;
            });
        }
        net_thread_ = std::thread([this] { net_loop(); });
        worker_thread_ = std::thread([this] { worker_loop(); });
        serve_thread_ = std::thread([this] { serve_loop(); });
    }
    return true;
}

void Node::stop()
{
    if (!running_.exchange(false)) return;
    jobs_cv_.notify_all();
    if (main_thread_.joinable()) main_thread_.join();
    if (net_thread_.joinable()) net_thread_.join();
    if (worker_thread_.joinable()) worker_thread_.join();
    serve_cv_.notify_all();
    if (serve_thread_.joinable()) serve_thread_.join();
    if (ep_) ep_->stop();
    ep_.reset();
    if (zmq_) zmq_->stop();
}

// ------------------------------------------------------------------ queries
#define LOCKED                                     \
    std::lock_guard<std::recursive_mutex> l_(mu_); \
    Txn t(*store_)

std::optional<Hash32> Node::tip()
{
    LOCKED;
    return state_.tip(t);
}
std::optional<uint32_t> Node::height()
{
    LOCKED;
    return state_.height(t);
}
std::optional<Hash32> Node::block_hash_at(uint32_t h)
{
    LOCKED;
    auto tp = state_.tip(t);
    auto ht = state_.height(t);
    if (!tp || !ht || h > *ht) return std::nullopt;
    return archive_.nth_ancestor(t, *tp, *ht - h);
}
std::optional<Header> Node::header(const Hash32& h)
{
    LOCKED;
    return archive_.header(t, h);
}
std::optional<Body> Node::body(const Hash32& h)
{
    LOCKED;
    return archive_.body(t, h);
}
std::optional<uint32_t> Node::block_height(const Hash32& h)
{
    LOCKED;
    return archive_.height(t, h);
}
bool Node::is_descendant(const Hash32& anc, const Hash32& desc)
{
    LOCKED;
    return archive_.is_descendant(t, anc, desc);
}
std::map<Hash32, uint32_t> Node::tx_inclusions(const Hash32& txid)
{
    LOCKED;
    return archive_.tx_inclusions(t, txid);
}
std::optional<Hash32> Node::best_main_verification(const Hash32& side)
{
    LOCKED;
    return archive_.best_main_verification(t, side);
}
std::vector<Hash32> Node::bmm_inclusions(const Hash32& side)
{
    LOCKED;
    std::vector<Hash32> r;
    for (auto& [m, res] : archive_.bmm_results(t, side))
        if (res == BmmResult::Verified) r.push_back(m);
    return r;
}
std::vector<std::pair<OutPoint, FilledOutput>> Node::utxos()
{
    LOCKED;
    return state_.utxos(t);
}
std::vector<std::pair<OutPoint, SpentOutput>> Node::stxos()
{
    LOCKED;
    return state_.stxos(t);
}
std::vector<std::pair<OutPoint, FilledOutput>> Node::utxos_by_addresses(const std::set<Address>& a)
{
    std::vector<std::pair<OutPoint, FilledOutput>> r;
    for (auto& [op, o] : utxos())
        if (a.count(o.address)) r.emplace_back(op, o);
    return r;
}
std::vector<std::pair<OutPoint, SpentOutput>> Node::stxos_by_addresses(const std::set<Address>& a)
{
    std::vector<std::pair<OutPoint, SpentOutput>> r;
    for (auto& [op, s] : stxos())
        if (a.count(s.output.address)) r.emplace_back(op, s);
    return r;
}
std::optional<WithdrawalBundle> Node::pending_withdrawal_bundle()
{
    LOCKED;
    auto p = state_.pending_bundle(t);
    if (!p) return std::nullopt;
    return p->first;
}
std::optional<uint32_t> Node::latest_failed_withdrawal_bundle_height()
{
    LOCKED;
    auto f = state_.latest_failed_bundle(t);
    if (!f) return std::nullopt;
    return f->first;
}
uint64_t Node::sidechain_wealth()
{
    LOCKED;
    return state_.sidechain_wealth(t);
}
std::vector<std::pair<Hash32, BitNameData>> Node::bitnames()
{
    LOCKED;
    std::vector<std::pair<Hash32, BitNameData>> r;
    for (auto& [n, rec] : state_.bitnames(t)) r.emplace_back(n, rec.current());
    return r;
}
std::optional<BitNameData> Node::bitname_current(const Hash32& name)
{
    LOCKED;
    auto r = state_.bitname(t, name);
    if (!r) return std::nullopt;
    return r->current();
}
std::optional<BitNameData> Node::bitname_at(const Hash32& name, uint32_t h)
{
    LOCKED;
    return state_.bitname_at(t, name, h);
}
std::optional<BlockIndexEvents> Node::block_index_events(const Hash32& block)
{
    LOCKED;
    auto h = archive_.height(t, block);
    if (!h) throw bt::sidechain::ArchiveError("NoHeight " + bt::hex_encode(block));
    auto tp = state_.tip(t);
    auto ht = state_.height(t);
    if (!tp || !ht || *h > *ht || archive_.nth_ancestor(t, *tp, *ht - *h) != block) return std::nullopt; // NotInCurrentChain
    return state_.block_index_events(t, *h);
}
std::optional<Transaction> Node::transaction(const Hash32& txid)
{
    LOCKED;
    auto inc = archive_.tx_inclusions(t, txid);
    if (!inc.empty()) {
        auto& [bh, idx] = *inc.begin(); // BTreeMap first_key_value
        auto b = archive_.body(t, bh);
        if (b && idx < b->transactions.size()) return b->transactions[idx];
    }
    auto it = mempool_.find(txid);
    if (it != mempool_.end()) return it->second.transaction;
    return std::nullopt;
}
std::optional<AuthorizedTransaction> Node::authorized_transaction(const Hash32& txid)
{
    LOCKED;
    auto it = mempool_.find(txid);
    if (it != mempool_.end()) return it->second;
    auto inc = archive_.tx_inclusions(t, txid);
    if (inc.empty()) return std::nullopt;
    auto& [bh, idx] = *inc.begin();
    auto b = archive_.body(t, bh);
    if (!b) return std::nullopt;
    auto ats = b->authorized_transactions();
    if (idx >= ats.size()) return std::nullopt;
    return ats[idx];
}
std::optional<std::pair<std::pair<AuthorizedTransaction, std::vector<FilledOutput>>, std::optional<std::pair<Hash32, uint32_t>>>>
Node::filled_transaction(const Hash32& txid)
{
    LOCKED;
    auto tp = state_.tip(t);
    for (auto& [bh, idx] : archive_.tx_inclusions(t, txid)) {
        if (tp && !archive_.is_descendant(t, bh, *tp)) continue;
        auto b = archive_.body(t, bh);
        if (!b) continue;
        auto ats = b->authorized_transactions();
        if (idx >= ats.size()) continue;
        auto ft = state_.fill_from_stxos(t, ats[idx].transaction);
        return std::make_pair(std::make_pair(ats[idx], ft.spent_utxos), std::optional<std::pair<Hash32, uint32_t>>(std::make_pair(bh, idx)));
    }
    auto it = mempool_.find(txid);
    if (it == mempool_.end()) return std::nullopt;
    try {
        auto ft = state_.fill(t, it->second.transaction);
        return std::make_pair(std::make_pair(it->second, ft.spent_utxos), std::optional<std::pair<Hash32, uint32_t>>());
    } catch (const StateError&) {
        return std::nullopt; // NoUtxo
    }
}
std::vector<AuthorizedTransaction> Node::mempool()
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    std::vector<AuthorizedTransaction> r;
    for (auto& [id, tx] : mempool_) r.push_back(tx);
    return r;
}
std::vector<PeerView> Node::peers()
{
    std::lock_guard<std::mutex> l(peers_mu_);
    std::vector<PeerView> r;
    for (auto& [c, p] : peers_) r.push_back({p.addr, p.connected, p.inbound});
    return r;
}
SyncProgress Node::sync_progress()
{
    std::lock_guard<std::mutex> l(sync_mu_);
    return sync_;
}

std::string Node::status()
{
    std::optional<uint32_t> h;
    {
        std::lock_guard<std::mutex> l(cache_mu_);
        h = cached_height_;
    }
    size_t np;
    {
        std::lock_guard<std::mutex> l(peers_mu_);
        np = peers_.size();
    }
    return "height " + (h ? std::to_string(*h) : std::string("none")) + ", " + std::to_string(np) + " peers, " + std::to_string(mempool_size_.load()) +
           " mempool txs";
}

void Node::refresh_cache()
{
    auto ti = our_tip_info();
    auto h = height();
    std::lock_guard<std::mutex> l(cache_mu_);
    cached_tip_info_ = ti;
    cached_height_ = h;
}

// ------------------------------------------------------------------ mempool (lib/mempool.rs)
void Node::mempool_put(const AuthorizedTransaction& tx)
{
    Hash32 txid = tx.transaction.txid();
    for (auto& op : tx.transaction.inputs)
        if (mempool_spent_.count(op.key())) throw StateError("UtxoDoubleSpent");
    for (auto& op : tx.transaction.inputs) mempool_spent_[op.key()] = txid;
    mempool_[txid] = tx;
    mempool_size_ = mempool_.size();
}

void Node::mempool_delete(const Hash32& txid)
{
    std::deque<Hash32> q{txid};
    while (!q.empty()) {
        Hash32 id = q.front();
        q.pop_front();
        auto it = mempool_.find(id);
        if (it == mempool_.end()) continue;
        for (auto& op : it->second.transaction.inputs) mempool_spent_.erase(op.key());
        size_t nout = it->second.transaction.outputs.size();
        mempool_.erase(it);
        mempool_size_ = mempool_.size();
        for (uint32_t v = 0; v < nout; v++) {
            auto s = mempool_spent_.find(OutPoint{OutPoint::Regular, id, v}.key());
            if (s != mempool_spent_.end()) q.push_back(s->second);
        }
    }
}

// Policy (kept, consensus-neutral): never take a txid already confirmed on the active
// chain back into the mempool, so our node does not relay or mine zero-input replays.
bool Node::confirmed_on_active_chain(const Txn& t, const Hash32& txid)
{
    auto tp = state_.tip(t);
    if (!tp) return false;
    for (auto& [bh, idx] : archive_.tx_inclusions(t, txid))
        if (archive_.header(t, bh) && archive_.is_descendant(t, bh, *tp)) return true;
    return false;
}

std::pair<std::vector<std::pair<AuthorizedTransaction, std::vector<FilledOutput>>>, uint64_t> Node::mempool_transactions(size_t n)
{
    LOCKED;
    std::vector<std::pair<AuthorizedTransaction, std::vector<FilledOutput>>> r;
    uint64_t fee = 0;
    std::set<std::array<uint8_t, 37>> spent;
    std::vector<AuthorizedTransaction> take;
    for (auto& [id, tx] : mempool_) {
        if (take.size() >= n) break;
        take.push_back(tx);
    }
    for (auto& tx : take) {
        bool conflict = false;
        for (auto& op : tx.transaction.inputs)
            if (spent.count(op.key())) conflict = true;
        Hash32 txid = tx.transaction.txid();
        if (conflict || confirmed_on_active_chain(t, txid)) {
            mempool_delete(txid);
            continue;
        }
        uint64_t f;
        try {
            f = state_.validate_transaction(t, tx);
        } catch (const StateError&) {
            mempool_delete(txid);
            continue;
        }
        auto ft = state_.fill(t, tx.transaction);
        if (fee + f < fee) break;
        fee += f;
        for (auto& op : tx.transaction.inputs) spent.insert(op.key());
        r.emplace_back(tx, ft.spent_utxos);
    }
    return {r, fee};
}

size_t Node::broadcast_transaction(const AuthorizedTransaction& tx)
{
    AuthorizedTransaction stored = tx;
    {
        LOCKED;
        Hash32 txid = tx.transaction.txid();
        state_.validate_transaction(t, tx);
        if (confirmed_on_active_chain(t, txid)) throw StateError("transaction already confirmed (replay refused by policy)");
        auto it = mempool_.find(txid);
        if (it == mempool_.end()) mempool_put(tx);
        else stored = it->second;
    }
    return relay_tx(stored, std::nullopt);
}

size_t Node::rebroadcast_transaction(const Hash32& txid)
{
    AuthorizedTransaction tx;
    {
        std::lock_guard<std::recursive_mutex> l(mu_);
        auto it = mempool_.find(txid);
        if (it == mempool_.end()) throw StateError("mempool error: Missing transaction " + bt::hex_encode(txid));
        tx = it->second;
    }
    return broadcast_transaction(tx);
}

void Node::remove_from_mempool(const Hash32& txid)
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    mempool_delete(txid);
}

void Node::invalidate_block(const Hash32& h)
{
    {
        LOCKED;
        // node/mod.rs:204-234: disconnect while the tip descends from the block, then mark it
        while (auto tp = state_.tip(t)) {
            if (!archive_.header(t, *tp) || !archive_.header(t, h) || !archive_.is_descendant(t, h, *tp)) break;
            disconnect_tip_(t);
        }
        // out of the side-tips index with its descendants (before mark_invalid drops the
        // successor lists), so the best ordered tip is never an invalidated block
        if (archive_.header(t, h)) side_tips_delete_body(t, archive_, side_tips_, h);
        archive_.mark_invalid(t, h);
        t.commit();
    }
    refresh_cache();
    if (on_tip_changed) on_tip_changed();
}

// ------------------------------------------------------------------ mainchain
bool Node::request_mainchain_ancestor_infos(const Hash32& main)
{
    std::lock_guard<std::mutex> ml(main_mu_);
    if (main.is_zero()) return true;
    {
        LOCKED;
        if (archive_.main_header(t, main)) return true;
    }
    // Fetch ancestors newest-first in batches (mainchain_task.rs:179-263), staged on disk
    // by height so the whole mainchain never sits in memory.
    Hash32 cur = main;
    uint64_t staged = 0;
    uint32_t tip_height = 0;
    bool first = true;
    for (;;) {
        if (!running_) return false;
        auto r = enforcer_->get_block_infos(cur, 999);
        if (!bt::enforcer::ok(r)) {
            LOG_WARN("GetBlockInfo %s: %s", bt::hex_encode_rev(cur.span()).c_str(), bt::enforcer::err(r).what().c_str());
            return false;
        }
        auto& infos = bt::enforcer::val(r);
        if (infos.empty()) return false;
        if (first) {
            tip_height = infos.front().first.height;
            first = false;
        }
        {
            Txn st(*store_);
            for (auto& [hi, bi] : infos) {
                Writer k;
                k.u32be(hi.height);
                Writer v;
                v.raw(hi.block_hash);
                v.raw(hi.prev_block_hash);
                v.raw(hi.work);
                bt::sidechain::enc_block_info(v, bi);
                st.put(T_MAIN_STAGE, k.buf, v.buf);
                staged++;
            }
            st.commit();
        }
        auto& last = infos.back().first;
        cur = last.prev_block_hash;
        {
            std::lock_guard<std::mutex> l(sync_mu_);
            sync_ = SyncProgress{SyncProgress::Headers, tip_height - last.height, tip_height, tip_height};
        }
        if (staged % 50000 < 1000) LOG_INFO("mainchain sync: fetched back to height %u", last.height);
        if (cur.is_zero()) break;
        LOCKED;
        if (archive_.main_header(t, cur)) break;
    }
    std::lock_guard<std::recursive_mutex> l(mu_);
    std::vector<std::pair<Bytes, Bytes>> rows;
    {
        Txn t(*store_);
        t.scan(T_MAIN_STAGE, [&](ByteSpan k, ByteSpan v) {
            rows.emplace_back(Bytes(k.begin(), k.end()), Bytes(v.begin(), v.end()));
            return true;
        });
    }
    {
        std::lock_guard<std::mutex> sl(sync_mu_);
        sync_ = SyncProgress{SyncProgress::Writing, 0, uint32_t(rows.size()), tip_height};
    }
    size_t i = 0;
    while (i < rows.size()) {
        Txn t(*store_);
        size_t n = 0;
        for (; n < 20000 && i < rows.size(); n++, i++) {
            Reader r(rows[i].second);
            bt::mainchain::BlockHeaderInfo hi;
            hi.height = uint32_t(rows[i].first[0]) << 24 | uint32_t(rows[i].first[1]) << 16 | uint32_t(rows[i].first[2]) << 8 | rows[i].first[3];
            hi.block_hash = r.array<32>();
            hi.prev_block_hash = r.array<32>();
            hi.work = r.array<32>();
            auto bi = bt::sidechain::dec_block_info(r);
            if (!archive_.main_header(t, hi.block_hash)) {
                archive_.put_main_header_info(t, hi);
                archive_.put_main_block_info(t, hi.block_hash, bi);
            }
            t.del(T_MAIN_STAGE, rows[i].first);
        }
        t.commit();
        std::lock_guard<std::mutex> sl(sync_mu_);
        sync_.done += uint32_t(n);
    }
    {
        std::lock_guard<std::mutex> sl(sync_mu_);
        sync_ = SyncProgress{};
    }
    LOG_DEBUG("mainchain sync: stored %zu header infos", rows.size());
    return true;
}

void Node::mainchain_loop()
{
    std::optional<Hash32> last_tip;
    bool checked = false;
    while (running_) {
        if (!checked) {
            // app.rs check_proto_support: wait for the validator service
            auto h = enforcer_->health("cusf.mainchain.v1.ValidatorService");
            if (!h) {
                auto tr = enforcer_->get_chain_tip();
                if (!bt::enforcer::ok(tr)) LOG_WARN("Waiting for CUSF mainchain service(s): %s", bt::enforcer::err(tr).what().c_str());
                else checked = true;
            } else {
                checked = *h;
                if (!*h) LOG_WARN("cusf.mainchain.v1.ValidatorService is not serving");
            }
        }
        if (checked) {
            auto tr = enforcer_->get_chain_tip();
            if (bt::enforcer::ok(tr)) {
                Hash32 mt = bt::enforcer::val(tr).block_hash;
                // a failed side-tips sync is retried on the next poll, as their mainchain
                // task restarts after 5 s and fails again the same way
                if (mt != last_tip && request_mainchain_ancestor_infos(mt) && sync_to_mainchain_tip(mt)) last_tip = mt;
            }
        }
        for (int i = 0; i < 20 && running_; i++) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// mainchain_task.rs sync_side_tips_to_tip + handle_block_event, then net_task.rs
// handle_mainchain_block_event. A mainchain reorg does NOT disconnect sidechain blocks whose
// BMM block left the active chain (quirk reproduced on purpose, side_tips.h): the state tip
// moves only when reorg_to_tip's better_tip prefers the best ordered side tip, or a peer's.
bool Node::sync_to_mainchain_tip(const Hash32& main_tip)
{
    size_t events = 0;
    {
        LOCKED;
        t.put(T_MAIN_TIP, Bytes{0}, main_tip.span());
        try {
            events = sync_side_tips(t, archive_, side_tips_, main_tip, [this](uint32_t done, uint32_t total, uint32_t tip_height) {
                std::lock_guard<std::mutex> sl(sync_mu_);
                sync_ = done == total ? SyncProgress{} : SyncProgress{SyncProgress::StateSync, done, total, tip_height};
            });
        } catch (const std::exception& e) {
            {
                std::lock_guard<std::mutex> sl(sync_mu_);
                sync_ = SyncProgress{};
            }
            LOG_ERROR("Mainchain task error: failed to sync side tips to %s: %s", bt::hex_encode_rev(main_tip.span()).c_str(), e.what());
            return false;
        }
        t.commit();
    }
    if (events) handle_mainchain_block_event();
    return true;
}

// net_task.rs:928-980
void Node::handle_mainchain_block_event()
{
    std::optional<std::pair<Hash32, SideTipInfo>> best;
    bool changed = false;
    try {
        LOCKED;
        while (auto tp = state_.tip(t)) {
            if (side_tips_.contains(t, *tp)) break;
            // Theirs (net_task.rs:943) calls state.disconnect_tip only (no 2WPD, no mempool).
            // A mainchain reorg never gets here: blocks leave the tip set only when their body
            // is deleted as invalid, which never happens to a state block.
            // Ours disconnects properly (2WPD + mempool): their path is unreachable for them,
            // ours is reached only after --bt-rebuild-side-tips or invalidate_block.
            LOG_WARN("state tip %s is not a side tip; disconnecting it", bt::hex_encode(*tp).c_str());
            disconnect_tip_(t);
            changed = true;
        }
        best = side_tips_.best(t);
        if (best && archive_.invalid(t, best->first)) best.reset(); // policy (cannot happen: removed at invalidation)
        t.commit();
    } catch (const std::exception& e) {
        LOG_ERROR("handle mainchain block event: %s", e.what());
        return;
    }
    if (changed) {
        refresh_cache();
        if (on_tip_changed) on_tip_changed();
    }
    if (!best) return;
    try {
        reorg_to_tip(TipRef{best->first, best->second.main_block_hash});
    } catch (const std::exception& e) {
        LOG_WARN("rejecting an invalid side tip %s: %s", bt::hex_encode(best->first).c_str(), e.what());
    }
}

/** submit_block: their mainchain task has normally handled the BMM block's ConnectBlock event
 *  before the miner submits, so the side tips first follow the enforcer's tip. */
bool Node::catch_up_mainchain()
{
    if (!enforcer_) return false;
    auto tr = enforcer_->get_chain_tip();
    if (!bt::enforcer::ok(tr)) return false;
    Hash32 mt = bt::enforcer::val(tr).block_hash;
    return request_mainchain_ancestor_infos(mt) && sync_to_mainchain_tip(mt);
}

void Node::put_body_(Txn& t, const Hash32& h, const Body& b)
{
    archive_.put_body(t, h, b);
    side_tips_put_body(t, archive_, side_tips_, h);
}

void Node::delete_body_(Txn& t, const Hash32& h)
{
    archive_.delete_body(t, h);
    side_tips_delete_body(t, archive_, side_tips_, h);
}

// Theirs stores any body whose header hash matches (net_task.rs:576-588) and finds a wrong
// one only at connect (then drops the peer). Ours, stricter and consensus-neutral (such a body
// fails connect anyway): an oversized body is refused, and a body whose parent is our tip is
// fully prevalidated (merkle root incl. the 1000-tx switch, fees, authorizations). The body
// of any other block cannot be checked against its header without that block's parent state
// (the merkle root commits to fees); it is checked at connect, deleted if wrong (re-requested
// from another peer), and the peer that sent the tip is banned. Empty = fine.
std::string Node::check_peer_body_(const Txn& t, const Hash32& want, const Body& b)
{
    if (borsh_bytes(b).size() > Body::MAX_SIZE) return "BodyTooLarge";
    auto hd = archive_.header(t, want);
    if (!hd) return {}; // invalidated meanwhile: not stored (put_body needs the header), no ban
    if (hd->prev_side_hash != state_.tip(t)) return {};
    try {
        state_.prevalidate(t, *hd, b);
    } catch (const StateError& e) {
        return e.what();
    }
    return {};
}

std::string Node::check_peer_body(const Hash32& want, const Body& b)
{
    LOCKED;
    return check_peer_body_(t, want, b);
}

void Node::receive_block(const Header& h, const Body& b)
{
    LOCKED;
    if (!archive_.header(t, h.hash())) archive_.put_header(t, h);
    if (!archive_.body(t, h.hash())) put_body_(t, h.hash(), b);
    t.commit();
}

// ------------------------------------------------------------------ connect / reorg (net_task.rs)
std::vector<Hash32> Node::main_ancestors(const Txn& t, const Hash32& from, const std::optional<Hash32>& stop)
{
    std::vector<Hash32> r;
    Hash32 cur = from;
    while (!cur.is_zero()) {
        if (stop && cur == *stop) break;
        auto m = archive_.main_header(t, cur);
        if (!m) throw bt::sidechain::ArchiveError("NoMainHeaderInfo " + bt::hex_encode_rev(cur.span()));
        r.push_back(cur);
        cur = m->prev;
    }
    return r;
}

void Node::connect_tip_(Txn& t, const Header& h, const Body& b, const TwoWayPegData& d)
{
    Hash32 bh = h.hash();
    auto pre = state_.prevalidate(t, h, b);
    state_.connect_prevalidated(t, h, b, pre);
    state_.connect_2wpd(t, d);
    archive_.put_header(t, h);
    put_body_(t, bh, b);
    for (auto& tx : b.transactions) mempool_delete(tx.txid());
}

// net_task.rs:117-216
void Node::disconnect_tip_(Txn& t)
{
    auto tip_hash = state_.tip(t);
    if (!tip_hash) throw StateError("NoTip");
    Header th = archive_.need_header(t, *tip_hash);
    auto tb = archive_.body(t, *tip_hash);
    if (!tb) throw StateError("missing body for the tip", true);
    uint32_t height = *state_.height(t);
    auto last_applied = [&](const std::vector<std::pair<uint32_t, std::pair<Hash32, uint32_t>>>& rows) -> std::optional<std::pair<Hash32, uint32_t>> {
        for (auto it = rows.rbegin(); it != rows.rend(); ++it) // rev_iter in key (memcmp) order
            if (it->second.second < height) return it->second;
        return std::nullopt;
    };
    auto dep = last_applied(state_.deposit_blocks(t));
    auto wd = last_applied(state_.bundle_event_blocks(t));
    std::optional<Hash32> start;
    if (dep && !wd) start = dep->first;
    else if (!dep && wd) start = wd->first;
    else if (dep && wd) {
        if (dep->second < wd->second) start = wd->first;
        else if (dep->second > wd->second) start = dep->first;
        else start = archive_.is_main_descendant(t, wd->first, dep->first) ? wd->first : dep->first;
    }
    TwoWayPegData d;
    auto anc = main_ancestors(t, th.prev_main_hash, start);
    for (auto it = anc.rbegin(); it != anc.rend(); ++it) {
        auto bi = archive_.main_block_info(t, *it);
        if (!bi.events.empty()) d.block_info.emplace_back(*it, bi);
    }
    state_.disconnect_2wpd(t, d);
    state_.disconnect_tip(t, th, *tb);
    // Their mempool.put error here aborts the whole reorg (SPEC #8); ours drops the
    // conflicting transaction and continues (kept fix, no consensus effect).
    auto txs = tb->authorized_transactions();
    for (auto it = txs.rbegin(); it != txs.rend(); ++it) {
        try {
            mempool_put(*it);
        } catch (const StateError&) {
        }
    }
}

void Node::publish_block(const Hash32& h, uint32_t height)
{
    if (!zmq_) return;
    Writer hw;
    hw.u32(height);
    zmq_->publish({Bytes{'h', 'a', 's', 'h', 'b', 'l', 'o', 'c', 'k'}, Bytes(h.begin(), h.end()), hw.buf});
}

// net_task.rs:227-430
bool Node::reorg_to_tip(const TipRef& new_tip, bool* invalid_body)
{
    std::vector<std::pair<Hash32, uint32_t>> published;
    {
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        // policy: never to an operator-invalidated block or a descendant of one
        if (archive_.invalid(t, new_tip.block_hash)) return false;
        auto tip_hash = state_.tip(t);
        auto tip_height = state_.height(t);
        std::optional<TipRef> tip;
        if (tip_hash) {
            auto bv = archive_.best_main_verification(t, *tip_hash);
            if (!bv) throw bt::sidechain::ArchiveError("NoBmmResult");
            tip = TipRef{*tip_hash, *bv};
            if (archive_.better_tip(t, *tip, new_tip) != std::optional<TipRef>(new_tip)) return false;
        }
        std::optional<Hash32> common;
        if (tip) common = archive_.last_common_ancestor(t, tip->block_hash, new_tip.block_hash);
        std::vector<std::pair<Header, Body>> apply; // newest first
        {
            std::optional<Hash32> cur = new_tip.block_hash;
            while (cur && cur != common) {
                if (archive_.invalid(t, *cur)) return false;
                auto h = archive_.header(t, *cur);
                auto b = archive_.body(t, *cur);
                if (!h || !b) return false;
                apply.emplace_back(*h, *b);
                cur = h->prev_side_hash;
            }
        }
        std::optional<uint32_t> common_height;
        if (common) common_height = archive_.height(t, *common);
        if (tip_height) {
            uint32_t disconnects = common ? *tip_height - *common_height : *tip_height + 1;
            try {
                for (uint32_t i = 0; i < disconnects; i++) disconnect_tip_(t);
            } catch (const StateError& e) {
                LOG_WARN("reorg to %s aborted: cannot disconnect: %s", bt::hex_encode(new_tip.block_hash).c_str(), e.what());
                return false;
            }
        }
        std::optional<Hash32> common_prev_main;
        if (common) common_prev_main = archive_.need_header(t, *common).prev_main_hash;
        auto batch_hashes = main_ancestors(t, apply.front().first.prev_main_hash, common_prev_main);
        uint32_t idx = 0;
        for (auto it = apply.rbegin(); it != apply.rend(); ++it, ++idx) {
            auto& [h, b] = *it;
            TwoWayPegData d;
            while (!batch_hashes.empty()) {
                Hash32 mh = batch_hashes.back();
                batch_hashes.pop_back();
                d.block_info.emplace_back(mh, archive_.main_block_info(t, mh));
                if (mh == h.prev_main_hash) break;
            }
            try {
                connect_tip_(t, h, b, d);
            } catch (const StateError& e) {
                LOG_WARN("block %s rejected: %s%s", bt::hex_encode(h.hash()).c_str(), e.what(), e.panic ? " (their node would panic)" : "");
                Txn dt(*store_);
                delete_body_(dt, h.hash());
                dt.commit();
                if (invalid_body) *invalid_body = true;
                return false;
            }
            published.emplace_back(h.hash(), (common_height ? *common_height + 1 : 0) + idx);
            auto nt = *state_.tip(t);
            auto bv = archive_.best_main_verification(t, nt);
            TipRef ntr{nt, bv ? *bv : Hash32{}};
            if (tip && archive_.better_tip(t, *tip, ntr) != std::optional<TipRef>(ntr)) continue;
            t.commit();
        }
        t.commit();
        LOG_INFO("synced to tip: %s (height %u)", bt::hex_encode(new_tip.block_hash).c_str(), *state_.height(t));
    }
    refresh_cache();
    for (auto& [h, ht] : published) publish_block(h, ht);
    if (on_tip_changed) on_tip_changed();
    return true;
}

// node/mod.rs:816-946
bool Node::submit_block(const Hash32& main_block_hash, const Header& h, const Body& b)
{
    Hash32 bh = h.hash();
    {
        LOCKED;
        if (h.prev_side_hash && !archive_.header(t, *h.prev_side_hash)) {
            LOG_ERROR("Rejecting block %s due to missing ancestor headers", bt::hex_encode(bh).c_str());
            return false;
        }
    }
    if (!request_mainchain_ancestor_infos(main_block_hash)) return false;
    catch_up_mainchain();
    {
        std::lock_guard<std::recursive_mutex> l(mu_);
        {
            Txn t(*store_);
            archive_.put_header(t, h);
            t.commit();
        }
        Txn r(*store_);
        auto res = archive_.bmm_results(r, bh);
        auto it = res.find(main_block_hash);
        if (it == res.end() || it->second != BmmResult::Verified) {
            LOG_ERROR("Rejecting block %s due to failing BMM verification", bt::hex_encode(bh).c_str());
            return false;
        }
        auto tp = state_.tip(r);
        std::optional<Hash32> common;
        if (tp) common = archive_.last_common_ancestor(r, *tp, bh);
        auto missing = archive_.missing_bodies(r, bh, common);
        if (!(missing.empty() || missing == std::vector<Hash32>{bh})) {
            LOG_ERROR("Rejecting block %s due to missing ancestor bodies", bt::hex_encode(bh).c_str());
            return false;
        }
        if (missing == std::vector<Hash32>{bh}) {
            Txn w(*store_);
            put_body_(w, bh, b);
            w.commit();
        }
    }
    bool ready;
    {
        LOCKED;
        ready = side_tips_tip_ready(t, archive_, side_tips_, TipRef{bh, main_block_hash});
    }
    if (!ready || !reorg_to_tip(TipRef{bh, main_block_hash})) {
        LOG_WARN("Not ready to reorg to %s", bt::hex_encode(bh).c_str());
        return false;
    }
    if (auto ht = height()) publish_block(bh, *ht); // their submit_block publishes once more
    if (auto p = pending_withdrawal_bundle()) {
        auto r = enforcer_->propose_withdrawal_bundle(p->tx_bytes());
        if (!bt::enforcer::ok(r)) LOG_WARN("Failed to propose withdrawal bundle %s: %s", bt::hex_encode_rev(p->m6id().span()).c_str(), bt::enforcer::err(r).what().c_str());
    }
    return true;
}

// ------------------------------------------------------------------ P2P
bool Node::connect_peer(const std::string& hostport_in, std::string& err)
{
    auto hp = bt::split_hostport(hostport_in, DEFAULT_PORT);
    if (!hp) {
        err = "invalid peer address";
        return false;
    }
    std::string hostport = hp->first.find(':') != std::string::npos ? "[" + hp->first + "]:" + std::to_string(hp->second) : hp->first + ":" + std::to_string(hp->second);
    if (!ep_) {
        err = "P2P disabled";
        return false;
    }
    {
        Txn t(*store_);
        t.put(T_PEERS, ByteSpan((const uint8_t*)hostport.data(), hostport.size()), {});
        t.commit();
    }
    std::lock_guard<std::mutex> l(peers_mu_);
    dial_targets_[hostport] = 0;
    return true;
}

bool Node::forget_peer(const std::string& hostport)
{
    bool existed;
    {
        Txn t(*store_);
        existed = t.del(T_PEERS, ByteSpan((const uint8_t*)hostport.data(), hostport.size()));
        t.commit();
    }
    std::lock_guard<std::mutex> l(peers_mu_);
    dial_targets_.erase(hostport);
    return existed;
}

void Node::post_job(std::function<void()> f)
{
    {
        std::lock_guard<std::mutex> l(jobs_mu_);
        jobs_.push_back(std::move(f));
    }
    jobs_cv_.notify_one();
}

std::optional<TipInfo> Node::our_tip_info()
{
    LOCKED;
    auto tp = state_.tip(t);
    if (!tp) return std::nullopt;
    auto bv = archive_.best_main_verification(t, *tp);
    if (!bv) return std::nullopt;
    TipInfo ti;
    ti.block_height = *state_.height(t);
    ti.tip = {*tp, *bv};
    ti.total_work_be = archive_.total_work(t, *bv).to_be();
    return ti;
}

void Node::send_request(bt::quic::ConnId c, const P2P::Request& q, size_t limit, std::function<void(std::optional<P2P::Response>)> fn)
{
    Bytes payload(magic_.begin(), magic_.end());
    append(payload, P2P::encode(q));
    if (!limit) {
        ep_->send(c, std::move(payload), 0, std::chrono::milliseconds(0), nullptr);
        return;
    }
    auto timeout = std::chrono::milliseconds(5000 + uint64_t(limit) / (64 * 1024) * 1000);
    auto magic = magic_;
    ep_->send(c, std::move(payload), limit + 4, timeout, [this, fn, magic](std::optional<Bytes> r) {
        if (!r || r->size() < 4 || !std::equal(magic.begin(), magic.end(), r->begin())) {
            post_job([fn] { fn(std::nullopt); });
            return;
        }
        std::optional<P2P::Response> resp;
        try {
            resp = P2P::decode_response(ByteSpan(r->data() + 4, r->size() - 4));
        } catch (const std::exception&) {
        }
        post_job([fn, resp] { fn(resp); });
    });
}

size_t Node::relay_tx(const AuthorizedTransaction& tx, std::optional<bt::quic::ConnId> except)
{
    if (!ep_) return 0;
    std::vector<bt::quic::ConnId> targets;
    {
        std::lock_guard<std::mutex> l(peers_mu_);
        for (auto& [c, p] : peers_)
            if (p.connected && c != except) targets.push_back(c);
    }
    P2P::Request q;
    q.kind = P2P::Request::PushTransaction;
    q.tx = tx;
    for (auto c : targets) send_request(c, q, bt::sidechain::TX_ACK_LIMIT, [](std::optional<P2P::Response>) {});
    return targets.size();
}

void Node::ban(bt::quic::ConnId c, const std::string& why)
{
    std::string ip;
    {
        std::lock_guard<std::mutex> l(peers_mu_);
        auto it = peers_.find(c);
        if (it == peers_.end()) return;
        ip = it->second.addr.ip;
        banned_[ip] = now_s() + 3600;
    }
    LOG_WARN("banning peer %s: %s", ip.c_str(), why.c_str());
    ep_->close(c, "banned: " + why);
}

// Requests from peers (peer/task.rs)
void Node::on_request(bt::quic::ConnId c, int64_t stream, Bytes payload)
{
    if (payload.size() < 4 || !std::equal(magic_.begin(), magic_.end(), payload.begin())) {
        ep_->close(c, "bad magic");
        return;
    }
    P2P::Request q;
    try {
        q = P2P::decode_request(ByteSpan(payload.data() + 4, payload.size() - 4));
    } catch (const std::exception& e) {
        ep_->close(c, std::string("bad request: ") + e.what());
        return;
    }
    auto respond = [&](const P2P::Response& r) {
        Bytes out(magic_.begin(), magic_.end());
        append(out, P2P::encode(r));
        ep_->respond(c, stream, std::move(out));
    };
    switch (q.kind) {
    case P2P::Request::Heartbeat: {
        ep_->finish(c, stream);
        bool changed;
        {
            std::lock_guard<std::mutex> l(peers_mu_);
            auto& p = peers_[c];
            Writer a, b;
            if (p.state) bt::sidechain::encode_peer_state(a, *p.state);
            bt::sidechain::encode_peer_state(b, q.heartbeat);
            changed = !p.state || a.buf != b.buf;
            p.state = q.heartbeat;
        }
        if (changed) post_job([this, c, ps = q.heartbeat] { handle_peer_state(c, ps); });
        return;
    }
    case P2P::Request::GetBlock: {
        P2P::Response r;
        LOCKED;
        auto h = archive_.header(t, q.block_hash);
        auto b = archive_.body(t, q.block_hash);
        if (h && b) {
            r.kind = P2P::Response::Block;
            r.header = *h;
            r.body = *b;
        } else {
            r.kind = P2P::Response::NoBlock;
            r.hash = q.block_hash;
        }
        respond(r);
        return;
    }
    case P2P::Request::GetHeaders: {
        P2P::Response r;
        LOCKED;
        if (archive_.header(t, q.end)) {
            std::set<Hash32> start(q.start.begin(), q.start.end());
            r.kind = P2P::Response::Headers;
            std::optional<Hash32> cur = q.end;
            while (cur && !start.count(*cur)) {
                auto h = archive_.header(t, *cur);
                if (!h) break;
                r.headers.push_back(*h);
                cur = h->prev_side_hash;
            }
            std::reverse(r.headers.begin(), r.headers.end());
        } else {
            r.kind = P2P::Response::NoHeader;
            r.hash = q.end;
        }
        respond(r);
        return;
    }
    case P2P::Request::PushTransaction: {
        Hash32 txid = q.tx.transaction.txid();
        P2P::Response r;
        r.hash = txid;
        bool ok = true;
        try {
            LOCKED;
            state_.validate_transaction(t, q.tx);
        } catch (const std::exception&) {
            ok = false;
        }
        r.kind = ok ? P2P::Response::TransactionAccepted : P2P::Response::TransactionRejected;
        respond(r);
        if (ok) {
            post_job([this, tx = q.tx, c, txid]() mutable {
                try {
                    LOCKED;
                    if (mempool_.count(txid) || confirmed_on_active_chain(t, txid)) return; // replays are not relayed (policy)
                    mempool_put(tx);
                } catch (const std::exception&) {
                    return;
                }
                relay_tx(tx, c);
            });
        }
        return;
    }
    }
}

// peer/task.rs, simplified: fetch any peer tip that is not ours and let reorg_to_tip's
// better_tip decide, after the same claimed-work and BMM checks (which ban).
void Node::handle_peer_state(bt::quic::ConnId c, const PeerState& ps)
{
    if (!ps.tip_info) return;
    const TipInfo pt = *ps.tip_info;
    {
        LOCKED;
        auto ours = state_.tip(t);
        if (ours && *ours == pt.tip.block_hash) return;
        if (archive_.invalid(t, pt.tip.block_hash)) return;
    }
    if (!request_mainchain_ancestor_infos(pt.tip.main_block_hash)) return;
    LOCKED;
    auto mh = archive_.main_header(t, pt.tip.main_block_hash);
    if (!mh) return;
    if (archive_.total_work(t, pt.tip.main_block_hash).to_be() != pt.total_work_be) {
        ban(c, "IncorrectTotalWork");
        return;
    }
    auto info = archive_.main_block_info(t, pt.tip.main_block_hash);
    if (info.bmm_commitment != pt.tip.block_hash) {
        ban(c, "BmmVerificationFailed");
        return;
    }
    // peer/task.rs:57-84: a peer tip whose main block is not on our side tips' mainchain is
    // ignored (no ban)
    if (!side_tips_peer_tip_relevant(t, archive_, side_tips_, pt.tip.main_block_hash)) return;
    if (archive_.header(t, pt.tip.block_hash)) {
        request_bodies(c, pt);
        return;
    }
    P2P::Request q;
    q.kind = P2P::Request::GetHeaders;
    q.end = pt.tip.block_hash;
    if (auto ours = state_.tip(t)) q.start = archive_.block_locator(t, *ours);
    uint32_t hh = std::min(pt.block_height, mh->height);
    send_request(c, q, bt::sidechain::headers_response_limit(hh), [this, c, pt](std::optional<P2P::Response> r) {
        if (!r || r->kind != P2P::Response::Headers) return;
        on_headers(c, pt, r->headers);
    });
}

void Node::on_headers(bt::quic::ConnId c, const TipInfo& target, const std::vector<Header>& hs)
{
    std::set<Hash32> mains;
    for (auto& h : hs)
        if (mains.insert(h.prev_main_hash).second && !request_mainchain_ancestor_infos(h.prev_main_hash)) return;
    {
        // one store transaction for the whole batch (one fsync instead of one per header)
        LOCKED;
        for (auto& h : hs) {
            Hash32 bh = h.hash();
            if (archive_.header(t, bh)) continue;
            if (archive_.invalid(t, bh)) break;
            if (h.prev_side_hash && !archive_.header(t, *h.prev_side_hash)) break;
            archive_.put_header(t, h);
        }
        t.commit();
    }
    {
        LOCKED;
        auto r = archive_.bmm_results(t, target.tip.block_hash);
        auto it = r.find(target.tip.main_block_hash);
        if (it == r.end() || it->second != BmmResult::Verified) {
            ban(c, "BmmVerificationFailed");
            return;
        }
    }
    request_bodies(c, target);
}

void Node::request_bodies(bt::quic::ConnId c, const TipInfo& target)
{
    std::vector<Hash32> missing;
    {
        LOCKED;
        auto tp = state_.tip(t);
        std::optional<Hash32> common;
        if (tp) common = archive_.last_common_ancestor(t, *tp, target.tip.block_hash);
        missing = archive_.missing_bodies(t, target.tip.block_hash, common);
    }
    if (missing.empty()) {
        try {
            TipRef nt{target.tip.block_hash, target.tip.main_block_hash};
            bool ready;
            {
                LOCKED;
                ready = side_tips_tip_ready(t, archive_, side_tips_, nt); // NewTipReady
            }
            bool invalid = false;
            if (ready) reorg_to_tip(nt, &invalid);
            // theirs drops the peer whose block fails to connect (net_task.rs:1257-1272)
            if (invalid) ban(c, "InvalidBlock");
        } catch (const std::exception& e) {
            LOG_WARN("reorg failed: %s", e.what());
        }
        return;
    }
    size_t n = std::min<size_t>(missing.size(), 100);
    auto remaining = std::make_shared<std::atomic<size_t>>(n);
    for (size_t i = 0; i < n; i++) {
        P2P::Request q;
        q.kind = P2P::Request::GetBlock;
        q.block_hash = missing[i];
        Hash32 want = missing[i];
        send_request(c, q, bt::sidechain::BLOCK_RESPONSE_LIMIT, [this, c, target, want, remaining](std::optional<P2P::Response> r) {
            std::string why;
            if (r && r->kind == P2P::Response::Block && r->header.hash() == want) {
                LOCKED;
                if (!archive_.body(t, want)) {
                    why = check_peer_body_(t, want, r->body);
                    if (why.empty()) {
                        try {
                            put_body_(t, want, r->body);
                            t.commit();
                        } catch (const std::exception& e) {
                            LOG_WARN("cannot store body %s: %s", bt::hex_encode(want).c_str(), e.what());
                        }
                    }
                }
            }
            if (!why.empty()) { // outside the node lock
                LOG_WARN("invalid body for %s from peer: %s", bt::hex_encode(want).c_str(), why.c_str());
                ban(c, "InvalidBody: " + why);
                return;
            }
            if (--*remaining == 0) request_bodies(c, target);
        });
    }
}

void Node::net_loop()
{
    int64_t last_hb = 0, last_status = 0;
    // Never blocks on the node lock or the mainchain: heartbeats must go out every second
    // or their peers drop us after the 5 s heartbeat timeout.
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        int64_t now = now_s();
        std::vector<std::string> to_dial;
        {
            std::lock_guard<std::mutex> l(peers_mu_);
            for (auto& [hp, when] : dial_targets_) {
                if (when < 0 || when > now) continue;
                bool connected = false;
                for (auto& [cid, p] : peers_)
                    if (p.dial == hp) connected = true;
                if (!connected) {
                    to_dial.push_back(hp);
                    when = -1;
                }
            }
        }
        for (auto& hp : to_dial) {
            auto parsed = bt::split_hostport(hp, DEFAULT_PORT);
            if (!parsed) {
                std::lock_guard<std::mutex> l(peers_mu_);
                dial_targets_.erase(hp);
                continue;
            }
            auto addrs = bt::quic::resolve(parsed->first, parsed->second);
            std::optional<bt::quic::SockAddr> a;
            for (auto& x : addrs)
                if (x.ip.find(':') == std::string::npos) {
                    a = x;
                    break;
                }
            std::lock_guard<std::mutex> l(peers_mu_);
            if (!a || banned_.count(a->ip)) {
                dial_targets_[hp] = now + 60;
                continue;
            }
            bool numeric = parsed->first.find_first_not_of("0123456789.") == std::string::npos;
            auto cid = ep_->connect(*a, numeric ? "localhost" : parsed->first);
            auto& p = peers_[cid];
            p.conn = cid;
            p.addr = *a;
            p.dial = hp;
        }
        if (now != last_hb) {
            last_hb = now;
            P2P::Request q;
            q.kind = P2P::Request::Heartbeat;
            {
                std::lock_guard<std::mutex> l(cache_mu_);
                q.heartbeat.tip_info = cached_tip_info_;
            }
            std::vector<bt::quic::ConnId> targets;
            {
                std::lock_guard<std::mutex> l(peers_mu_);
                for (auto& [c, p] : peers_)
                    if (p.connected) targets.push_back(c);
            }
            for (auto c : targets) send_request(c, q, 0, nullptr);
        }
        if (now - last_status >= 60) {
            last_status = now;
            LOG_INFO("%s", status().c_str());
        }
    }
}

void Node::post_serve(std::function<void()> f)
{
    {
        std::lock_guard<std::mutex> l(serve_mu_);
        serve_.push_back(std::move(f));
    }
    serve_cv_.notify_one();
}

void Node::serve_loop()
{
    while (running_) {
        std::function<void()> job;
        {
            std::unique_lock<std::mutex> l(serve_mu_);
            serve_cv_.wait_for(l, std::chrono::milliseconds(200), [&] { return !serve_.empty() || !running_; });
            if (!serve_.empty()) {
                job = std::move(serve_.front());
                serve_.pop_front();
            }
        }
        if (job) {
            try {
                job();
            } catch (const std::exception& e) {
                LOG_WARN("serve: %s", e.what());
            }
        }
    }
}

void Node::worker_loop()
{
    while (running_) {
        std::function<void()> job;
        {
            std::unique_lock<std::mutex> l(jobs_mu_);
            jobs_cv_.wait_for(l, std::chrono::milliseconds(200), [&] { return !jobs_.empty() || !running_; });
            if (!jobs_.empty()) {
                job = std::move(jobs_.front());
                jobs_.pop_front();
            }
        }
        if (job) {
            try {
                job();
            } catch (const std::exception& e) {
                LOG_WARN("net task: %s", e.what());
            }
        }
    }
}

} // namespace bitnames
