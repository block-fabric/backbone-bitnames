# Differential tests for the test machine (BitNames, slot 2)

Their binaries are not built or run on the development PC. On the separate test machine run
the octobocto plain-bitnames fork **v0.18.2** (`bitnames` = plain_bitnames_app,
`bitnames-cli`; tag 7b4c309, HEAD a38200d) and bip300301_enforcer (regtest preset) next to
our `bitnames`, and compare. Every test records both sides' outputs; any difference stops
the run and saves the block/tx. Both nodes expose `get_block_template` + `connect_block`, so
one generator drives both; `get_block_index` is the best per-block hook.

## A. Byte-level (no network)

1. **Codecs**: random `Transaction` (all four `TxData` kinds, every `Update` variant, every
   optional field of `MutableBitNameData`, IPv4/IPv6 sockets, empty and long memos),
   `AuthorizedTransaction`, `Header`, `Body`, `Coinbase`, P2P `RequestMessage`/`ResponseMessage`:
   bincode decode/encode and borsh encode on both sides (their `plain_bitnames_types` in a
   small harness); compare accept/reject (invalid ristretto points, identity, non-canonical
   scalars, non-UTF-8 plain names), re-encoded bytes, txid, block hash.
2. **Merkle**: bodies with 0-1100 txs and coinbase outputs (random fees/sizes, withdrawal
   outputs, memos): `Body::compute_merkle_root` on both, especially counts 999, 1000, 1001,
   1023, 1024, 1025 (CBMT vs levelized switch) and fee sums near u64::MAX (their panic, our
   reject).
3. **FROST**: random/malformed keys and signatures over `0x00 || borsh(tx)` and with the
   Arbitrary DST (255): accept/reject must match `frost-ristretto255` batch verification.
4. **Deposit addresses**: `from_deposit_address` + base58 fallback on random strings
   (`s2_` with 0..64 checksum chars, upper case, `_` inside the address, `s9_`, non-UTF-8):
   resulting `Address` must match.
5. **Seq ids**: `BitNameSeqId` Display/FromStr for 0..2^32 samples (including > 10^8, the
   4-segment form, and FromStr edge cases with leading zeros and overflow).
6. **Bundles**: random withdrawal sets (all address kinds/networks, equal fees/values,
   >400k WU) -> m6id and tx bytes from `collect_withdrawal_bundle`.
7. **Wallet**: for 20 mnemonics compare the first 50 addresses (`get_new_address`), 10
   encryption keys, 10 verifying keys, `get_wallet_master_xvk`, `get_wallet_master_xesk`, and
   the reservation commitment for 10 names (`reserve_bitname` on theirs creates zero-input txs;
   on ours the commitment is the same, the tx also spends a coin when one exists).
8. **ECIES**: their `encrypt_msg` -> our `decrypt_msg` and back, empty and 1 MB messages,
   tampered MAC/tag/nonce.

## B. Regtest, side by side (one enforcer feeding both nodes)

9. **Templates/blocks**: generate blocks from each node's `get_block_template`, connect them
   on the other with `connect_block`; after every block compare `get_block`,
   `get_block_index`, `list_utxos`, `list_stxos` (as sets), `bitnames`, `bitname_data` for every
   name, `sidechain_wealth`, `pending_withdrawal_bundle`, `latest_failed_withdrawal_bundle_height`.
10. **Names**: reserve, register (all six data fields, IPv6 forms incl. `::ffff:a.b.c.d`),
    update with Delete/Retain/Set per field, transfer, several updates of one name in one
    block, `bitname_data` at each step; then `invalidate_block` back and forth (history pops).
11. **Quirk blocks** crafted on regtest (study §5): two registrations of one name in one
    block (both accept; compare state; then try to disconnect - both must fail the same way);
    zero-input reservation replayed in a later block and inside one block; coinbase with a
    BitName/BitNameReservation output (both reject at connect); a BatchIcann tx (both
    reject); a block of exactly 1000 txs (levelized root) and 999 txs.
12. **Deposits**: `s2_…_<1..64 hex>`, bare base58, `s9_…`, non-UTF-8, 19/21-byte payloads,
    several per block and in the BMM block itself -> `get_block_index` deposits and owners.
13. **Bundles**: withdrawal -> Pending -> Submitted -> Succeeded after the regtest threshold;
    Failed after max age; resubmitted failed bundle; unknown bundle Submitted+Succeeded at
    height > 0 (both halt) and at height 0.
14. **Reorgs**: sidechain reorg via `invalidate_block`; mainchain reorgs over a side tip with
    and without deposits; equal-height competing tips; reorg across a replayed zero-input tx
    (their node cannot disconnect it; ours must refuse identically and keep the tip).
    **Quirk reproduced on purpose** (bitnames.md quirk 9): a mainchain reorg that removes the
    BMM blocks of the last sidechain blocks keeps those blocks on both nodes (lab 2026-10-21:
    theirs kept 2, ours then dropped them: fixed). Check after each step, both nodes: tip,
    height, `get_best_mainchain_block_hash`, UTXOs: (a) reorg removing the BMM blocks of the
    last 2 blocks, no commitments on the new branch: tip unchanged; (b) then mine on either
    node: both templates build an empty block on the last block whose prev_main survived and
    both switch to it; (c) a competing block committed on the new branch at lower height:
    both keep the old tip until it is beaten by `better_tip`; (d) mine on a kept block: BMM
    fails on both; (e) reorg back and away again over a kept block's BMM block, and a reorg of
    a commitment to a block never relayed: theirs halts with `missing sidechain tip` (logs
    `Mainchain task error`) and keeps its tip; ours does the same only when built with
    `REPRODUCE_SIDE_TIPS_HALT = true` (default: warns and keeps following).
15. **Mempool/relay**: `submit_transaction`, `broadcast_transaction`,
    `rebroadcast_transaction`, `create_transfer(_many)`, `create_withdrawal`,
    `reserve_bitname`, `register_bitname` on either side, PushTransaction answers
    (Accepted/Rejected) both ways, mined by the other; ours must not relay a txid already
    confirmed (policy) but must accept a block containing one.
16. **Mining**: `mine` on our node against the regtest enforcer (BMM request, first-event
    confirm, block submitted, bundle proposed); their node follows. ZMQ: subscribe to both
    `--zmq-addr` with pyzmq/libzmq SUB on topic `hashblock` and compare the multipart messages
    (hash, height LE) per block, including reorgs.

## C. Mixed network and surface

17. Their node syncs from ours only (theirs `--add-peer` ours, no seeds) and ours from theirs
    only, on regtest and betanet; heartbeat total-work checks must not ban either side.
18. RPC JSON byte-diff for all 58 served methods (both servers, same state), including errors,
    `null` results and named vs positional params; `bitnames-cli` (theirs) against our node
    and ours against theirs, every subcommand. Note: our `get_paymail` is served only where
    the wallet methods are (same server with the default single `--rpc-addr`).
19. Orchestrator/BitWindow drive our binary with their flags (`--mainchain-grpc-host/port`,
    `--file-log-level`, `-z/--zmq-addr`, `--network betanet`, …): start, sync, wallet pages,
    names, paymail, deposits, withdrawals, mining; the seed index (esplora facade) against our
    RPC (`get_block_index`, `get_block_hash`, `get_transaction`, …).
20. Shadow validation on betanet for weeks: tip, `get_block_index` per block, `bitnames`,
    `list_utxos` hash and pending bundle compared every block.
