// The kit's pages BitNames draws itself (chain/LocalPages.svelte): the drop-in node is not a Core node, so its Home,
// wallet, peg, explorer and node pages are the drop-in pages (chain/dropin), in the kit's places. See doc/app.md.
import type { PageId } from '../lib/nav.svelte';

export const LOCAL_OVERRIDES: readonly PageId[] = ['home', 'overview', 'send', 'receive', 'transactions', 'peg', 'explorer', 'node'];

/** The node's options are its own (Settings → Node, chain/settings.ts), not a Core node's. */
export const KIT_NODE_OPTIONS: boolean = false;
