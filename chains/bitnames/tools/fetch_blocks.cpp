// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// bitnames-fetch-blocks: download every BitNames block from a public betanet peer over the
// BitNames QUIC protocol (client role only), for known-answer tests and archiving. The
// chain is discovered from the peer itself: its heartbeat gives the tip, GetHeaders
// (no start) the whole header chain, then GetBlock for each body.
//
//   bitnames-fetch-blocks --out blocks.bin [--peer seed.beta.ecash.eu.com:4002] [--parallel 8]
//
// blocks.bin records: u32 height, u32 length, bincode(ResponseMessage::Block) as received.
#include <bitnames/chain.h>

#include <bt/parse.h>
#include <bt/quic.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <fstream>
#include <map>
#include <mutex>
#include <thread>

using namespace bitnames;

int main(int argc, char** argv)
{
    std::string peer = "seed.beta.ecash.eu.com:4002", out;
    int parallel = 8;
    for (int i = 1; i + 1 < argc; i += 2) {
        std::string a = argv[i], v = argv[i + 1];
        if (a == "--peer") peer = v;
        else if (a == "--out") out = v;
        else if (a == "--parallel") parallel = int(std::clamp<uint64_t>(bt::parse_u64(v).value_or(8), 1, 64));
    }
    if (out.empty()) {
        std::fprintf(stderr, "usage: bitnames-fetch-blocks --out blocks.bin [--peer host:port] [--parallel N]\n");
        return 2;
    }
    auto hp = bt::split_hostport(peer, DEFAULT_PORT);
    if (!hp) return 2;
    auto addrs = bt::quic::resolve(hp->first, hp->second);
    std::optional<bt::quic::SockAddr> remote;
    for (auto& a : addrs)
        if (a.ip.find(':') == std::string::npos) {
            remote = a;
            break;
        }
    if (!remote) {
        std::fprintf(stderr, "cannot resolve %s\n", hp->first.c_str());
        return 1;
    }
    std::fprintf(stderr, "peer %s -> %s\n", hp->first.c_str(), remote->to_string().c_str());
    auto magic = magic_bytes(Network::Betanet);
    std::mutex mu;
    std::condition_variable cv;
    bool connected = false, closed = false;
    std::optional<bt::sidechain::TipInfo> tip;
    bt::quic::Endpoint* epp = nullptr;
    bt::quic::Callbacks cb;
    cb.on_connected = [&](bt::quic::ConnId, const bt::quic::SockAddr&, bool) {
        std::lock_guard<std::mutex> l(mu);
        connected = true;
        cv.notify_all();
    };
    cb.on_request = [&](bt::quic::ConnId c, int64_t s, Bytes p) {
        if (epp) epp->finish(c, s);
        if (p.size() < 4 || !std::equal(magic.begin(), magic.end(), p.begin())) return;
        try {
            auto q = P2P::decode_request(ByteSpan(p.data() + 4, p.size() - 4));
            if (q.kind == P2P::Request::Heartbeat && q.heartbeat.tip_info) {
                std::lock_guard<std::mutex> l(mu);
                if (!tip) {
                    tip = q.heartbeat.tip_info;
                    cv.notify_all();
                }
            }
        } catch (const std::exception&) {
        }
    };
    cb.on_closed = [&](bt::quic::ConnId, const std::string& r) {
        std::lock_guard<std::mutex> l(mu);
        closed = true;
        std::fprintf(stderr, "closed: %s\n", r.c_str());
        cv.notify_all();
    };
    bt::quic::Options opt;
    opt.accept_inbound = false;
    bt::quic::Endpoint ep(cb, opt);
    epp = &ep;
    std::string err;
    if (!ep.start({"0.0.0.0", 0}, err)) return 1;
    auto conn = ep.connect(*remote, hp->first);
    auto with_magic = [&](const Bytes& b) {
        Bytes r(magic.begin(), magic.end());
        append(r, b);
        return r;
    };
    std::atomic<bool> stop_hb{false};
    std::thread hb([&] {
        P2P::Request q; // heartbeat, no tip, version 0.18.2
        Bytes payload = with_magic(P2P::encode(q));
        while (!stop_hb) {
            ep.send(conn, payload, 0, std::chrono::milliseconds(0), nullptr);
            for (int i = 0; i < 10 && !stop_hb; i++) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    auto finish = [&](int rc) {
        stop_hb = true;
        hb.join();
        ep.close(conn, "done");
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        ep.stop();
        return rc;
    };
    {
        std::unique_lock<std::mutex> l(mu);
        cv.wait_for(l, std::chrono::seconds(30), [&] { return (connected && tip) || closed; });
        if (!tip) {
            std::fprintf(stderr, "no tip from peer\n");
            l.unlock();
            return finish(1);
        }
    }
    std::fprintf(stderr, "peer tip %s height %u (main %s)\n", bt::hex_encode(tip->tip.block_hash).c_str(), tip->block_height,
                 bt::hex_encode_rev(tip->tip.main_block_hash.span()).c_str());
    // headers genesis..tip
    std::vector<Header> headers;
    {
        P2P::Request q;
        q.kind = P2P::Request::GetHeaders;
        q.end = tip->tip.block_hash;
        std::optional<Bytes> resp;
        bool done = false;
        ep.send(conn, with_magic(P2P::encode(q)), bt::sidechain::headers_response_limit(tip->block_height) + 4, std::chrono::seconds(60),
                [&](std::optional<Bytes> r) {
                    std::lock_guard<std::mutex> g(mu);
                    resp = std::move(r);
                    done = true;
                    cv.notify_all();
                });
        std::unique_lock<std::mutex> l(mu);
        cv.wait_for(l, std::chrono::seconds(90), [&] { return done || closed; });
        if (!resp || resp->size() < 4) {
            std::fprintf(stderr, "GetHeaders failed\n");
            l.unlock();
            return finish(1);
        }
        auto r = P2P::decode_response(ByteSpan(resp->data() + 4, resp->size() - 4));
        if (r.kind != P2P::Response::Headers) {
            std::fprintf(stderr, "GetHeaders: response kind %u\n", unsigned(r.kind));
            l.unlock();
            return finish(1);
        }
        headers = std::move(r.headers);
    }
    // check the chain links genesis -> tip
    for (size_t i = 0; i < headers.size(); i++) {
        auto want = i ? std::optional<Hash32>(headers[i - 1].hash()) : std::nullopt;
        if (headers[i].prev_side_hash != want) {
            std::fprintf(stderr, "headers not linked at %zu\n", i);
            return finish(1);
        }
    }
    if (headers.empty() || headers.back().hash() != tip->tip.block_hash) {
        std::fprintf(stderr, "headers do not end at the tip (%zu)\n", headers.size());
        return finish(1);
    }
    std::fprintf(stderr, "%zu headers\n", headers.size());
    std::ofstream of(out, std::ios::binary | std::ios::trunc);
    std::map<uint32_t, Bytes> done;
    int inflight = 0, failures = 0;
    uint32_t next_write = 0, written = 0;
    std::deque<uint32_t> todo;
    for (uint32_t h = 0; h < headers.size(); h++) todo.push_back(h);
    std::unique_lock<std::mutex> l(mu);
    while ((!todo.empty() || inflight > 0) && !closed && failures < 20) {
        while (inflight < parallel && !todo.empty()) {
            uint32_t h = todo.front();
            todo.pop_front();
            P2P::Request q;
            q.kind = P2P::Request::GetBlock;
            q.block_hash = headers[h].hash();
            inflight++;
            l.unlock();
            ep.send(conn, with_magic(P2P::encode(q)), bt::sidechain::BLOCK_RESPONSE_LIMIT + 4, std::chrono::seconds(60), [&, h](std::optional<Bytes> resp) {
                std::lock_guard<std::mutex> g(mu);
                inflight--;
                if (!resp || resp->size() < 4 || !std::equal(magic.begin(), magic.end(), resp->begin())) {
                    failures++;
                    todo.push_back(h);
                } else {
                    done[h] = Bytes(resp->begin() + 4, resp->end());
                }
                cv.notify_all();
            });
            l.lock();
        }
        cv.wait_for(l, std::chrono::seconds(1));
        while (!done.empty() && done.begin()->first == next_write) {
            auto it = done.begin();
            uint32_t h = it->first;
            next_write++;
            try {
                auto r = P2P::decode_response(it->second);
                if (r.kind != P2P::Response::Block || r.header.hash() != headers[h].hash()) {
                    std::fprintf(stderr, "height %u: bad block response\n", h);
                    failures++;
                } else {
                    uint32_t len = uint32_t(it->second.size());
                    of.write((const char*)&h, 4);
                    of.write((const char*)&len, 4);
                    of.write((const char*)it->second.data(), len);
                    if (++written % 500 == 0) std::fprintf(stderr, "  %u blocks\n", written);
                }
            } catch (const std::exception& e) {
                std::fprintf(stderr, "height %u: decode error %s\n", h, e.what());
                failures++;
            }
            done.erase(it);
        }
    }
    l.unlock();
    std::fprintf(stderr, "wrote %u blocks, %d failures\n", written, failures);
    return finish(failures ? 1 : 0);
}
