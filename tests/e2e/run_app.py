#!/usr/bin/env python3
# Copyright (c) 2026 The Backbone developers
# Distributed under the MIT software license.
"""End-to-end run of bitnames-app on a local eCash regtest (doc/app.md "Tests"): slot 2, app.js in its page (a name
reserved, registered with a record, looked up; node B resolves it too); the runner is core/tests/e2e/dropin_app.py.

    run_app.py --bin build-app/chains/bitnames --backboned <backboned> --tmp <dir> --shots <dir> [--base-port 49830]
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "core" / "tests" / "e2e"))
from dropin_app import Chain, main  # noqa: E402
from dropin_regtest import wait_for  # noqa: E402

READS = [("getblockcount", []), ("get_best_sidechain_block_hash", []), ("get_best_mainchain_block_hash", []), ("list_utxos", []),
         ("pending_withdrawal_bundle", []), ("latest_failed_withdrawal_bundle_height", []), ("sidechain_wealth", []), ("balance", []),
         ("get_wallet_addresses", []), ("get_wallet_utxos", []), ("openapi_schema", []), ("list_peers", []), ("bitnames", []),
         ("list_mempool", []), ("mainchain_sync_progress", []), ("my_utxos", [])]


def on_signal(msg, run):
    """SIGNAL registered <hash> <ipv4>: node B (another node, no app) resolves the name the app registered."""
    words = msg.split()
    if words[0] != "registered":
        return []
    name_hash, ipv4 = words[1], words[2]
    data = wait_for(lambda: run.b.bitname_data(name_hash), "node B resolves the name", 120, 1)
    print(f"  node B resolves {name_hash[:16]}…: {data}", flush=True)
    return [] if data.get("socket_addr_v4") == ipv4 else [f"node B resolves the name to {data}, not {ipv4}"]


def more_reads(a, addrs):
    names = a.bitnames()
    return [("bitname_data", [n[0] if isinstance(n, list) else n]) for n in names[:3]]


if __name__ == "__main__":
    sys.exit(main(Chain(stem="bitnames", title="BitNames", slot=2, script=HERE / "app.js", reads=READS, url_flag="--bt-mainchain-grpc-url",
                        node_args=["--bt-no-zmq"], on_signal=on_signal, more_reads=more_reads)))
