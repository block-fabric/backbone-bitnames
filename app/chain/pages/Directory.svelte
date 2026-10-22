<script lang="ts">
  // The name directory: every name of the registry (by its id: the chain keeps no words of a name, only the wallet knows
  // its own), and a look-up of any name in words: free, or what it points to.
  import DataTable from '../../components/DataTable.svelte';
  import SafeText from '../../components/SafeText.svelte';
  import Icon from '../../components/Icon.svelte';
  import { errorText } from '../../lib/dialogs.svelte';
  import { t } from '../../lib/i18n.svelte';
  import type { Column } from '../../lib/table';
  import { drop, follow } from '../dropin/store.svelte';
  import { bn, records, type NameData, type Resolved } from '../bn';

  $effect(() => follow());
  type Row = { hash: string; name?: string; data: NameData };
  let rows = $state<Row[]>([]);
  let query = $state('');
  let found = $state<Resolved | null>(null);
  let error = $state('');
  let filter = $state('');
  let selected = $state<string | null>(null);
  let sortKey = $state<string | null>('seq');
  let sortDir = $state<'asc' | 'desc'>('desc');

  $effect(() => {
    void drop.version;
    bn.directory(2000)
      .then((r) => (rows = r))
      .catch((e) => (error = errorText(e)));
  });

  async function lookUp() {
    const q = query.trim();
    if (!q) return;
    try {
      found = await bn.resolve(q);
      error = '';
    } catch (e) {
      error = errorText(e);
    }
  }

  const columns: Column<Row>[] = [
    { key: 'seq', label: 'No.', value: (r) => r.data.seq_id, width: '7.5rem', mono: true },
    { key: 'name', label: 'Name', value: (r) => r.name ?? '', width: '12rem' },
    { key: 'hash', label: 'Id', value: (r) => r.hash, width: 'minmax(12rem, 1fr)', mono: true },
    { key: 'records', label: 'Records', value: (r) => records(r.data).map(([l]) => l).join(', '), width: '14rem' },
  ];
</script>

<div class="page directory">
  <header class="page-head"><h1>{t('Name directory')}</h1></header>
  <section class="panel">
    <form
      class="panel-body row lookup"
      onsubmit={(e) => {
        e.preventDefault();
        lookUp();
      }}
    >
      <input type="search" class="grow" placeholder={t('Look up a name')} aria-label={t('Look up a name')} bind:value={query} />
      <button type="submit" class="btn small"><Icon name="search" size={15} /> {t('Look up')}</button>
    </form>
    {#if found}
      <div class="panel-body found">
        <h2><SafeText text={found.name} /></h2>
        {#if !found.registered}
          <p class="good"><Icon name="check" size={15} /> {t('Free: nobody registered it.')}</p>
        {:else}
          <dl class="facts">
            <dt>{t('Id')}</dt><dd class="mono break">{found.hash}</dd>
            <dt>{t('Registered as no.')}</dt><dd>{found.data?.seq_id}</dd>
            {#each records(found.data) as [label, value] (label)}<dt>{t(label)}</dt><dd class="mono break"><SafeText text={value} /></dd>{/each}
            {#if records(found.data).length === 0}<dt>{t('Records')}</dt><dd class="muted">{t('none')}</dd>{/if}
          </dl>
        {/if}
      </div>
    {/if}
  </section>
  {#if error}<p class="error">{error}</p>{/if}
  <div class="row head">
    <h2 class="grow">{rows.length === 1 ? t('1 name registered') : t('%1 names registered', rows.length)}</h2>
    <input type="search" placeholder={t('Filter')} aria-label={t('Filter the names')} bind:value={filter} />
  </div>
  <div class="holder">
    <DataTable {rows} {columns} key={(r) => r.hash} {filter} bind:selected bind:sortKey bind:sortDir label={t('Names')} empty={t('No name registered yet')} fit>
      {#snippet cell(row, column)}
        {#if column.key === 'seq'}<span class="mono">{row.data.seq_id}</span>
        {:else if column.key === 'name'}{#if row.name}<strong><SafeText text={row.name} /></strong>{:else}<span class="faint">—</span>{/if}
        {:else if column.key === 'hash'}<span class="mono">{row.hash}</span>
        {:else}{records(row.data).map(([l]) => t(l)).join(', ') || '—'}{/if}
      {/snippet}
    </DataTable>
  </div>
</div>

<style>
  .directory {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    height: 100%;
  }
  .lookup {
    gap: 0.5rem;
  }
  .found h2 {
    margin: 0 0 0.5rem;
  }
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.35rem 1rem;
    margin: 0;
  }
  .facts dt {
    color: var(--text-muted);
  }
  .facts dd {
    margin: 0;
  }
  .break {
    word-break: break-all;
  }
  .good {
    color: var(--positive);
    display: flex;
    gap: 0.35rem;
    align-items: center;
  }
  .head input {
    width: 14rem;
  }
  .holder {
    flex: 1;
    min-height: 16rem;
  }
  .error {
    color: var(--negative);
  }
</style>
