# bitnames-app: our app on the BitNames drop-in

`bitnames-app` is BitNames with our sidechain app: the sidechain template's window, trusted dialog and interface kit,
with pages for BitNames' own data model (UTXOs, names reserved then registered, their records, withdrawal bundles,
eCash as the mainchain). The node is `bitnames`, next to the app, unchanged: the app starts it as its child and talks
to its app RPC. Consensus, P2P and the LayerTwo JSON-RPC (plain_bitnames 0.18.2, 58 methods) are the drop-in's own and
stay byte for byte what they are; the app layer is off unless the node is started with `--bt-app-rpc-port`.

The design shared by every drop-in app (why a thin client, the app RPC, the privileges, one backup phrase by BIP-85,
the pack, security, tests) is [core/doc/app.md](../core/doc/app.md). This page is BitNames' part.

## Build and run

```
cmake -S . -B build-app -DBT_BUILD_APP=ON -DBT_KIT_DIR=<sidechain-template repo>   # GTK 3 + WebKitGTK 4.1, npm
cmake --build build-app -j4
build-app/chains/bitnames/bitnames-app                 # betanet, the enforcer at http://localhost:50051
build-app/chains/bitnames/bitnames-app --network regtest --mainchain-grpc-url http://127.0.0.1:50051 --node-arg=--bt-no-zmq
cmake --build build-app --target bitnames-app-pack     # build-app/pack/bitnames: the pack for the unified wallet
```

The app gives the node BitNames' own flag for the mainchain interface (`--bt-mainchain-grpc-url`, the manifest's
`mainchainUrlFlag`). The node's ZMQ publisher keeps LayerTwo's default (127.0.0.1:28002); `--node-arg=--bt-no-zmq`
turns it off (a second node on the same machine needs that or its own `--zmq-addr`).

## The pages

The drop-in pages (`core/app/ui`, see Thunder's doc/app.md for the list: Home, Overview, Send, Receive, Activity,
Drivechains, the explorer, the node, Settings → Node and → Wallet) and BitNames' own (`app/chain`):

- **Get a name**: type a name; the page says whether it is free (`bitnames.resolve`), then two steps, each asked in
  the trusted dialog: **reserve** (`reserve_bitname [name]`: only a commitment goes on the chain, so nobody learns the
  name before it is registered) and, once the reservation is in a block, **register** (`register_bitname [name,
  records?]`: an IPv4 address and port, a paymail fee; the dialog shows each record as the node parsed it). Our app
  asks for a coin before reserving: LayerTwo's wallet reserves without an input when it has none, a reservation anyone
  can replay.
- **My names**: the wallet's names with their records, the reservations waiting to be registered, the registrations
  waiting for their block (`bitnames.names`).
- **Name directory**: every name of the registry (by its id: the chain keeps no words of a name; the wallet's own in
  words, to a reader of the wallet only) and a look-up of any name in words (`bitnames.resolve`).
- Home's **My names** card; the activity names each name's row (registered, received, reserved: the reserved name in
  words from the wallet).

Names and records are text anyone chose on the chain: shown as data (the kit's `SafeText`: never translated, its
direction isolated), and every cell of the CSV export neutralised against spreadsheet formulas.

## What the pages use of the node (app/manifest.json)

- **Reads**: the LayerTwo reads by name (the same handlers and JSON): `balance`, `bitname_data`, `bitnames`,
  `format_deposit_address`, `get_best_mainchain_block_hash`, `get_best_sidechain_block_hash`, `get_block`,
  `get_block_hash`, `get_bmm_inclusions`, `get_paymail`, `get_stxos`, `get_transaction`, `get_transaction_info`,
  `get_utxos`, `get_wallet_addresses`, `get_wallet_utxos`, `getblockcount`, `latest_failed_withdrawal_bundle_height`,
  `list_mempool`, `list_peers`, `list_stxos`, `list_utxos`, `mainchain_sync_progress`, `my_utxos`, `openapi_schema`,
  `pending_withdrawal_bundle`, `sidechain_wealth`; and `getmainchaininfo`, `getbalances`, `getblockchaininfo`,
  `getnetworkinfo`, `uptime`.
- **Confirmed** (only through `rpc.confirmed`): `create_transfer [dest, value_sats, fee_sats, memo_hex?]`,
  `create_transfer_many`, `create_withdrawal`, `create_deposit`, `mine`, `reserve_bitname [name]`,
  `register_bitname [name, bitname_data?]`.
- **Host**: the shared `dropin.*` and `bitnames.names` (exercises `get_wallet_utxos`, `bitnames`), `bitnames.resolve`
  (`bitname_data`), `bitnames.directory` (`bitnames`; names in words only with `get_wallet_addresses`).

## Tests

- `tests/test_bitnames_appui.cpp`: every LayerTwo method's reply byte-identical with and without the app layer (58
  methods), the app RPC's reads equal to the LayerTwo results (an error of LayerTwo's an error of the app RPC), the
  phrase flows, the unified wallet's phrase, wallet ownership only for a wallet reader, the names (the wallet's names
  refused to a reader of the chain only; a look-up; a reservation without a coin refused before any question; a
  registration asked with its records in words; records the node cannot parse refused), the manifest.
- `app/chain/bn.test.ts` (vitest): reserve then register through `rpc.confirmed` with LayerTwo's parameters, the steps
  from what the node says, nothing outside the manifest; `npx svelte-check`.
- `tests/e2e/run_app.py` (a build with `-DBT_APP_TEST_HOOKS=ON`; xvfb-run): a local eCash regtest (backboned
  `-regtest -ecashregtest=betanet -grpc`, slot 2 proposed and acked), bitnames-app runs node A, a headless BitNames
  node B is the other side: the app starts, the phrase is made in the trusted dialog, 10 ECX deposited, 1.5 ECX sent,
  0.25 ECX received, the name `backbone-e2e` reserved and registered with an IPv4 record (both asked), resolved by the
  app and by node B, 2 ECX withdrawn and paid on eCash; then A's LayerTwo replies byte-identical without and with the
  app layer. Screenshots of every page, dark and light.

```
python3 tests/e2e/run_app.py --bin build-app/chains/bitnames --backboned <backboned> --tmp <dir> --shots <dir> --base-port 49830
```
