// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// BitNames node: state + archive + mempool on one store, the mainchain link (enforcer
// gRPC), block connection with two-way-peg windows and reorgs (port of the plain-bitnames
// fork v0.18.2 lib/node/{mod.rs, net_task.rs, mainchain_task.rs}), the QUIC P2P layer and
// the ZMQ "hashblock" publisher.
#pragma once

#include <bitnames/chain.h>
#include <bitnames/side_tips.h>
#include <bitnames/state.h>

#include <bt/enforcer.h>
#include <bt/kv.h>
#include <bt/quic.h>
#include <bt/zmq.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

namespace bitnames {

struct NodeConfig {
    std::string datadir;
    Network network = Network::Betanet;
    std::optional<std::array<uint8_t, 4>> magic_override;
    bt::quic::SockAddr net_addr{"0.0.0.0", DEFAULT_PORT};
    std::string mainchain_grpc_url = "http://127.0.0.1:50051";
    std::vector<std::string> add_peers; // host:port
    std::vector<std::string> server_names;
    bool use_seeds = true;
    bool p2p = true;
    std::optional<bt::quic::SockAddr> zmq_addr; // nullopt: no publisher
    bool rebuild_side_tips = false;             // --bt-rebuild-side-tips
};

struct PeerView {
    bt::quic::SockAddr address;
    bool connected = false;
    bool inbound = false;
};

/** types/lib.rs MainchainSyncProgress */
struct SyncProgress {
    enum Phase : uint8_t { Idle, Headers, Writing, StateSync } phase = Idle;
    uint32_t done = 0, total = 0, tip_height = 0;
};

class Node {
public:
    explicit Node(NodeConfig cfg);
    ~Node();
    bool start(std::string& err);
    void stop();

    // ---- queries (all take the node lock)
    std::optional<Hash32> tip();
    std::optional<uint32_t> height();
    std::optional<Hash32> block_hash_at(uint32_t height);
    std::optional<Header> header(const Hash32& h);
    std::optional<Body> body(const Hash32& h);
    std::optional<uint32_t> block_height(const Hash32& h);
    bool is_descendant(const Hash32& anc, const Hash32& desc);
    std::map<Hash32, uint32_t> tx_inclusions(const Hash32& txid);
    std::optional<Hash32> best_main_verification(const Hash32& side);
    std::vector<Hash32> bmm_inclusions(const Hash32& side);
    std::vector<std::pair<OutPoint, FilledOutput>> utxos();
    std::vector<std::pair<OutPoint, SpentOutput>> stxos();
    std::vector<std::pair<OutPoint, FilledOutput>> utxos_by_addresses(const std::set<Address>& a);
    std::vector<std::pair<OutPoint, SpentOutput>> stxos_by_addresses(const std::set<Address>& a);
    std::optional<WithdrawalBundle> pending_withdrawal_bundle();
    std::optional<uint32_t> latest_failed_withdrawal_bundle_height();
    uint64_t sidechain_wealth();
    std::vector<std::pair<Hash32, BitNameData>> bitnames();
    std::optional<BitNameData> bitname_current(const Hash32& name);
    std::optional<BitNameData> bitname_at(const Hash32& name, uint32_t height);
    /** get_block_index_events: only for blocks on the current chain. */
    std::optional<BlockIndexEvents> block_index_events(const Hash32& block);
    /** try_get_transaction: first inclusion by block hash, else the mempool. */
    std::optional<Transaction> transaction(const Hash32& txid);
    /** get_authorized_transaction: mempool first, then the first inclusion. */
    std::optional<AuthorizedTransaction> authorized_transaction(const Hash32& txid);
    /** try_get_filled_transaction: inclusion on the current chain (filled from STXOs) or the
     *  mempool; second = (block, index) or nullopt for the mempool. */
    std::optional<std::pair<std::pair<AuthorizedTransaction, std::vector<FilledOutput>>, std::optional<std::pair<Hash32, uint32_t>>>>
    filled_transaction(const Hash32& txid);
    std::vector<AuthorizedTransaction> mempool();
    std::vector<PeerView> peers();
    SyncProgress sync_progress();

    // ---- actions
    /** Node::submit_block. Returns accepted-as-new-tip. */
    bool submit_block(const Hash32& main_block_hash, const Header& h, const Body& b);
    /** validate, add to mempool (if new), relay; returns the number of peers it went to. */
    size_t broadcast_transaction(const AuthorizedTransaction& tx);
    size_t rebroadcast_transaction(const Hash32& txid);
    void remove_from_mempool(const Hash32& txid);
    void invalidate_block(const Hash32& h);
    bool connect_peer(const std::string& hostport, std::string& err);
    bool forget_peer(const std::string& hostport);
    bool request_mainchain_ancestor_infos(const Hash32& main);
    /** Move the side tips to main_tip (mainchain_task.rs sync_side_tips_to_tip) and, when
     *  that (dis)connected mainchain blocks, run net_task.rs handle_mainchain_block_event.
     *  False when the side tips cannot follow (their mainchain task fails the same way and
     *  retries); the mainchain headers must be stored. */
    bool sync_to_mainchain_tip(const Hash32& main_tip);
    /** Tests: run the chain logic on a store without starting the node's threads. */
    void attach_store(std::unique_ptr<bt::kv::Store> s) { store_ = std::move(s); }
    /** Store a header and body as a peer's GetBlock answer does, without reorging. */
    void receive_block(const Header& h, const Body& b);
    /** The checks a peer's GetBlock body passes before it is stored; empty = accepted. */
    std::string check_peer_body(const Hash32& block, const Body& b);
    /** node/mod.rs get_transactions(n): mempool in txid order, revalidated, conflicts dropped. */
    std::pair<std::vector<std::pair<AuthorizedTransaction, std::vector<FilledOutput>>>, uint64_t> mempool_transactions(size_t n);

    bt::enforcer::Client& enforcer() { return *enforcer_; }
    Archive& archive() { return archive_; }
    State& state() { return state_; }
    SideTips& side_tips() { return side_tips_; }
    std::recursive_mutex& lock() { return mu_; }
    bt::kv::Store& store() { return *store_; }
    const NodeConfig& config() const { return cfg_; }
    /** Called after the tip changes (wallet refresh). */
    std::function<void()> on_tip_changed;
    std::string status();

private:
    NodeConfig cfg_;
    std::unique_ptr<bt::kv::Store> store_;
    State state_;
    Archive archive_;
    SideTips side_tips_;
    std::unique_ptr<bt::enforcer::Client> enforcer_;
    std::unique_ptr<bt::zmq::Publisher> zmq_;
    std::recursive_mutex mu_;
    std::map<Hash32, AuthorizedTransaction> mempool_;            // LMDB txid order
    std::map<std::array<uint8_t, 37>, Hash32> mempool_spent_;
    std::atomic<bool> running_{false};
    std::thread main_thread_, net_thread_, worker_thread_, serve_thread_;
    std::mutex main_mu_;
    std::mutex sync_mu_;
    SyncProgress sync_;

    void connect_tip_(bt::kv::Txn& t, const Header& h, const Body& b, const bt::mainchain::TwoWayPegData& d);
    void disconnect_tip_(bt::kv::Txn& t);
    /** invalid_body: set when a block on the way failed to connect (its body was deleted). */
    bool reorg_to_tip(const TipRef& new_tip, bool* invalid_body = nullptr);
    std::vector<Hash32> main_ancestors(const bt::kv::Txn& t, const Hash32& from, const std::optional<Hash32>& stop);
    void mempool_put(const AuthorizedTransaction& tx);
    void mempool_delete(const Hash32& txid);
    bool confirmed_on_active_chain(const bt::kv::Txn& t, const Hash32& txid);
    void put_body_(bt::kv::Txn& t, const Hash32& h, const Body& b);
    void delete_body_(bt::kv::Txn& t, const Hash32& h);
    void handle_mainchain_block_event();
    std::string check_peer_body_(const bt::kv::Txn& t, const Hash32& block, const Body& b);
    bool catch_up_mainchain();
    void mainchain_loop();
    void publish_block(const Hash32& h, uint32_t height);

    // P2P
    struct Peer {
        bt::quic::ConnId conn = 0;
        bt::quic::SockAddr addr;
        std::string dial;
        bool connected = false, inbound = false;
        std::optional<bt::sidechain::PeerState> state;
    };
    std::unique_ptr<bt::quic::Endpoint> ep_;
    std::mutex peers_mu_;
    std::map<bt::quic::ConnId, Peer> peers_;
    std::map<std::string, int64_t> dial_targets_;
    std::map<std::string, int64_t> banned_;
    std::array<uint8_t, 4> magic_{};
    // The P2P loop reads only these (never the node lock or the store), so a long store
    // write cannot delay heartbeats past their 5 s timeout (which gets us banned).
    std::mutex cache_mu_;
    std::optional<bt::sidechain::TipInfo> cached_tip_info_;
    std::optional<uint32_t> cached_height_;
    std::atomic<size_t> mempool_size_{0};
    void refresh_cache();
    std::mutex jobs_mu_;
    std::condition_variable jobs_cv_;
    std::deque<std::function<void()>> jobs_;
    void post_job(std::function<void()> f);
    void net_loop();
    void worker_loop();
    void serve_loop();
    void post_serve(std::function<void()> f);
    std::mutex serve_mu_;
    std::condition_variable serve_cv_;
    std::deque<std::function<void()>> serve_;
    void on_request(bt::quic::ConnId c, int64_t stream, Bytes payload);
    void send_request(bt::quic::ConnId c, const P2P::Request& q, size_t limit, std::function<void(std::optional<P2P::Response>)> fn);
    void handle_peer_state(bt::quic::ConnId c, const bt::sidechain::PeerState& ps);
    void on_headers(bt::quic::ConnId c, const bt::sidechain::TipInfo& target, const std::vector<Header>& hs);
    void request_bodies(bt::quic::ConnId c, const bt::sidechain::TipInfo& target);
    void ban(bt::quic::ConnId c, const std::string& why);
    std::optional<bt::sidechain::TipInfo> our_tip_info();
    size_t relay_tx(const AuthorizedTransaction& tx, std::optional<bt::quic::ConnId> except);
};

} // namespace bitnames
