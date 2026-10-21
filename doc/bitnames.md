# BitNames (eCash slot 2): drop-in client

`bitnames` replaces the octobocto fork of plain-bitnames (`plain_bitnames_app`, shipped as
`bitnames`) v0.18.x on eCash betanet. Consensus, P2P, mainchain link, CLI flags and JSON-RPC
follow fork tag v0.18.2 (7b4c309; 0.18.0-0.18.2 have the same consensus), the rules every
betanet BitNames block was made under (study Part II BitNames §1). LayerTwo's own
plain-bitnames 0.17.2 has no betanet network and different hashes; it is not the target.

## Status

| Milestone | State | Evidence |
|---|---|---|
| M1 codecs/hashes | done | All 2,209 betanet blocks (0..2208) fetched from `seed.beta.ecash.eu.com:4002` over QUIC with `bitnames-fetch-blocks`: bincode decode -> re-encode byte-exact, header chain linked, every id and merkle root equal to the seed index (heights 1-2205); empty-block root `812c9708…bdbb`; the 151 txs the index serves as borsh hex round-trip and hash to their txids |
| M2 state machine | done | Full replay of slot 2 with every check (`tests/test_bitnames_replay.cpp`): 2,209 BMM commitments in the child of `prev_main` (genesis at mainchain 968,910, before the reported activation 968,998), 8 FROST signatures, 1,081 tx inclusions of 151 distinct txids (1,073 zero-input reservations), 8 registrations (seq `1739-0029`…`1739-0729`), 12 deposits (all in `get_block_index`), sidechain wealth 749,018,653 sat = the 7.49 ECX CTIP; rollback newest-first to height 1905 (below that their rules fail, quirk 2) and reconnect to an identical state |
| M3 mainchain link | done | gRPC (TLS) to `https://enforcer.beta.ecash.ninja`: health, chain tip, GetBlockInfo ancestors back to genesis (973,889 header infos), BMM verification of all blocks, 2WPD windows; pre-activation BMM accepted as reported |
| M4 drop-in surface | done (first version) | binary `bitnames` with their flags/defaults, `bitnames-cli` with their subcommands, 58 JSON-RPC methods with serde shapes, ZMQ `hashblock`; from an empty datadir our node synced to the live tip (2213, `b88d3b08…`, = the seed index) from the public seed peer; the peer kept our connection (0 disconnects) after we advertised our tip; restart resumes at the tip. mingw64 cross-build produces static `bitnames.exe`, `bitnames-cli.exe` |

## Drop-in surface

* **CLI** (fork app/cli.rs): `--add-peer`, `-d/--datadir` (default `<data_dir>/plain_bitnames`),
  `--file-log-level` (WARN), `--headless` (accepted, no GUI), `--log-dir` (default
  `<datadir>/logs/v0.18.2`), `--log-level` (DEBUG; one step lower without `--headless`, as
  theirs), `--mainchain-grpc-host` (127.0.0.1), `--mainchain-grpc-port` (50051),
  `--mnemonic-seed-phrase-path`, `-n/--net-addr` (0.0.0.0:4002), `--network`
  (betanet|forknet|regtest|signet), `--network-magic`, `-p/--private-rpc-addr`,
  `-r/--rpc-addr` (both 127.0.0.1:6002; different values split public/private exactly like
  theirs), `--server-name`, `--wallet-dir`, `-z/--zmq-addr` (127.0.0.1:28002). Unknown flags
  are logged and ignored. Ours start with `--bt-`: `--bt-mainchain-grpc-url` (https enforcer),
  `--bt-rpc-allowed-origin/-host`, `--bt-rpc-allow-external`, `--bt-no-seeds`, `--bt-no-p2p`,
  `--bt-no-zmq`.
* **JSON-RPC** (fork rpc-api/lib.rs, app/rpc_server.rs): public: openapi_schema,
  broadcast_transaction, bitname_data, bitnames, connect_block, get_block, get_block_hash,
  get_block_index, get_bmm_inclusions, get_best_mainchain_block_hash,
  get_best_sidechain_block_hash, get_stxos, get_transaction, get_authorized_transaction,
  get_transaction_info, get_utxos, getblockcount, latest_failed_withdrawal_bundle_height,
  list_mempool, list_peers, list_stxos, list_utxos, mainchain_sync_progress,
  pending_withdrawal_bundle, rebroadcast_transaction, sidechain_wealth, submit_transaction;
  private: connect_peer, forget_peer, invalidate_block, stop; wallet: balance, create_deposit,
  create_transfer, create_transfer_many, create_withdrawal, decrypt_msg, encrypt_msg,
  format_deposit_address, generate_mnemonic, get_block_template, get_new_address,
  get_new_encryption_key, get_new_verifying_key, get_paymail, get_wallet_addresses,
  get_wallet_master_xvk, get_wallet_master_xesk, get_wallet_utxos, mine, my_utxos,
  register_bitname, reserve_bitname, set_seed_from_mnemonic, sign_arbitrary_msg,
  sign_arbitrary_msg_as_addr, sign_transaction, verify_signature. The 59th method of their
  API, `bitname_commit`, is served by third-party commitment servers, not the node;
  `bitnames-cli resolve-commit` calls it (RFC 8785 canonical JSON, blake3 checked).
  Shapes: hex hashes and memos, base58 addresses, `bn-svk1…`/`bn-enc1…` Bech32m keys,
  `[u8; 32]` commitments as number arrays, `"1739-0029"` seq ids, externally tagged enums
  (`{"BitcoinSats": n}`, `"BitName"`, `{"BitNameReservation": [txid, commitment]}`), paymail
  keyed by the outpoint's JSON text. Parameter errors are -32602, application errors -1.
* **P2P**: QUIC v1/TLS 1.3, no ALPN, magic `cc 19 c2 84` (betanet; regtest 80, signet 81,
  forknet 82), port 4002, `Block{header, body}` responses, 10 MiB block / 2 KiB-per-header /
  256 B ack limits, heartbeat every second; seed `seed.beta.ecash.eu.com:4002`. The P2P loop
  reads only a cached tip, so store writes never delay heartbeats past their 5 s timeout
  (a late heartbeat gets a peer dropped and refused for a while).
* **ZMQ**: PUB on `--zmq-addr`, multipart `hashblock`, 32-byte block hash, height as u32 LE,
  once per connected block and once more for a submitted block (as theirs).
* **Wallet**: BIP-39 (tiny-bip39) seed; master = BIP32-Ed25519 XPrv from sha256(seed),
  re-hashed until valid; tx keys m/0'/i, encryption keys m/1'/i, message keys m/2'/i (V2);
  addresses from index 0; reservation nonce keyed_hash(blake3(sk), name). Import their wallet
  by mnemonic. ECIES = libes 0.9.1 (x25519, HKDF-SHA256, AES-256-GCM, HMAC-SHA256).
* **Datadir**: `backbone-bitnames.sqlite` and `backbone-wallet.sqlite` (owner-only, 0600 in
  0700 directories) next to where theirs keep LMDB; we resync from peers.

## Consensus quirks reproduced (tests/test_bitnames_quirks.cpp, test_bitnames_replay.cpp)

1. Duplicate registration of one name in one block: accepted (validation reads the pre-block
   DB), the second overwrites the record, both tokens exist, the first seq id is orphaned,
   and the block can no longer be disconnected (`Missing`).
2. Zero-input transactions: valid without signatures and replayable; a replay overwrites the
   UTXO and `reservations[txid]`; disconnecting the replay deletes the original's entries, so
   the original block cannot be disconnected (`MissingReservation`). On betanet 37 txids are
   confirmed in more than one block (one 105 times), and their rules cannot disconnect below
   height 1904 (`betanet_rollback_and_reconnect`): a reorg deeper than that is impossible for
   their nodes and therefore for ours.
3. Merkle switch: fee/size CBMT below 1000 transactions, a duplicate-last levelized tree from
   1000 (`MERKLE_LEVELIZED_FROM`).
4. Coinbase content checked only at connect: prevalidate accepts BitName/reservation coinbase
   outputs, connect rejects (`BadCoinbaseOutputContent`); withdrawal outputs are allowed.
5. BatchIcann never validates (verifying key None).
6. Deposit addresses: `s2_<b58>_<any non-empty hex prefix of sha256, any case>` or bare base58,
   anything else credits `Address::ALL_ZEROS`.
7. Registration must burn a reservation committing to keyed_hash(nonce, name); counts must
   balance; withdrawal outputs cannot be spent by transactions; no fees required.
8. Shared core rules as Thunder: no intra-block spends, unclaimed fees burned, bundle builder
   `break`, pending bundle never expires, unknown bundle confirmed at height > 0 halts,
   `deposit_blocks` little-endian keys, fork choice `better_tip`, first genesis sticks.
Where their node panics (assert/expect) ours rejects (`StateError::panic`).

## Kept (consensus-neutral) and deviations

* Our wallet's `reserve_bitname` also spends one coin back to us when it has one, so the
  reservation's txid is unique and cannot be replayed (theirs makes zero-input reservations).
* Mempool: a txid already confirmed on the active chain is not taken back or relayed; blocks
  containing replays are still accepted. A conflict when re-adding a disconnected block's
  transactions drops that transaction instead of aborting the reorg (SPEC #8).
* Templates take at most 999 transactions (stay on the CBMT side of the switch).
* RPC hardening as backbone-thunder (no CORS unless allowed, Host check, JSON content type,
  loopback unless `--bt-rpc-allow-external`); `get_paymail` (reads the wallet) only on the
  server that carries the wallet methods (theirs also puts it on the public one).
* Owner-only datadir, wallet, store and log files. Header batches are written in one store
  transaction.
* `openapi_schema` lists the methods instead of utoipa's full schema; `get_block` of an
  unknown block is an error (theirs panics the handler); no GUI.
* Mainchain: we poll `GetChainTip` (2 s); peer sync is the simplified decision table of
  backbone-thunder (same outcome, traffic may differ); `side_tips` is not ported.

## Remaining

1. Differential runs on the test machine (doc/differential-tests.md), especially wallet key
   vectors against their wallet, ECIES byte compatibility, RPC JSON byte-diffs, quirk blocks
   on regtest, bundles Succeeded/Failed, their node syncing from ours (our P2P port was not
   reachable from the internet here, so "their node dials us" is untested).
2. Windows binaries built but not run on Windows.
3. Thunder's node still has the old heartbeat path (tip info under a try-lock, status under
   the node lock) and can drop a peer during long store writes; port the cached-tip fix and
   move both nodes onto one templated node in the core.
4. Live ZMQ check with a libzmq subscriber (our raw ZMTP subscriber test passes).
5. Initial mainchain sync takes ~15 min (974k header infos, 999 per call) and the first store
   write of those infos several minutes on this disk; their node does the same work.
