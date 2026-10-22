<script lang="ts">
  // BitNames' card on Home: the wallet's names, and getting one.
  import Icon from '../components/Icon.svelte';
  import SafeText from '../components/SafeText.svelte';
  import Card from '../views/home/Card.svelte';
  import { t } from '../lib/i18n.svelte';
  import { go } from '../lib/nav.svelte';
  import { drop } from './dropin/store.svelte';
  import { bn, type Names } from './bn';

  let names = $state<Names | null>(null);
  $effect(() => {
    void drop.version;
    if (drop.seed?.hasSeed) bn.names().then((n) => (names = n)).catch(() => undefined);
  });
</script>

<Card title={t('My names')} icon="tag" open={() => go('names' as never)} openLabel={t('Open My names')}>
  <div class="big num">{names?.owned.length ?? 0}<span class="unit">{t('names')}</span></div>
  {#if names?.owned.length}
    <p class="list"><SafeText text={names.owned.slice(0, 4).map((n) => n.name ?? n.hash.slice(0, 10)).join(' · ')} /></p>
  {:else}
    <p class="muted small">{t('Reserve a name, then register it with what it points to.')}</p>
  {/if}
  {#snippet actions()}
    <button type="button" class="btn small" onclick={() => go('register' as never)}><Icon name="plus" size={15} /> {t('Get a name')}</button>
  {/snippet}
</Card>

<style>
  .big {
    font-size: 1.65rem;
    font-weight: 650;
    margin-bottom: 0.4rem;
  }
  .big .unit {
    font-size: 0.85rem;
    font-weight: 500;
    color: var(--text-muted);
    margin-inline-start: 0.4rem;
  }
  .list {
    margin: 0;
    font-weight: 600;
  }
  .small {
    font-size: 0.85rem;
    margin: 0;
  }
</style>
