<script lang="ts">
  // Settings' tabs of the drop-in: the node the app runs, and the wallet's backup phrase.
  import NodeSettings from './dropin/NodeSettings.svelte';
  import WalletSettings from './dropin/WalletSettings.svelte';
  let { tab }: { tab: string } = $props();
</script>

{#if tab === 'dropnode'}<NodeSettings />{:else if tab === 'dropwallet'}<WalletSettings />{/if}
