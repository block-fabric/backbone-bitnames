<script lang="ts">
  // My names: the names this wallet holds, what each points to, and reservations waiting to be registered.
  import CopyButton from '../../components/CopyButton.svelte';
  import SafeText from '../../components/SafeText.svelte';
  import Icon from '../../components/Icon.svelte';
  import { errorText } from '../../lib/dialogs.svelte';
  import { t } from '../../lib/i18n.svelte';
  import { go } from '../../lib/nav.svelte';
  import SetupWallet from '../dropin/SetupWallet.svelte';
  import { drop, follow } from '../dropin/store.svelte';
  import { bn, records, type Names } from '../bn';

  $effect(() => follow());
  let names = $state<Names | null>(null);
  let error = $state('');
  $effect(() => {
    void drop.version;
    bn.names()
      .then((n) => ((names = n), (error = '')))
      .catch((e) => (error = errorText(e)));
  });
</script>

<div class="page mynames">
  <header class="page-head row">
    <h1 class="grow">{t('My names')}</h1>
    <button type="button" class="btn primary small" onclick={() => go('register' as never)}><Icon name="plus" size={15} /> {t('Get a name')}</button>
  </header>
  {#if drop.seed && !drop.seed.hasSeed}
    <SetupWallet compact />
  {:else}
    {#if error}<p class="error">{error}</p>{/if}
    {#if names && names.owned.length === 0 && !names.registering?.length}
      <section class="panel empty">
        <div class="panel-body">
          <Icon name="tag" size={28} />
          <p>{t('No name yet.')}</p>
          <button type="button" class="btn" onclick={() => go('register' as never)}>{t('Get one')}</button>
        </div>
      </section>
    {/if}
    <div class="grid">
      {#each names?.owned ?? [] as n (n.hash)}
        <section class="panel name">
          <div class="panel-head row">
            <span class="tagmark"><Icon name="tag" size={16} /></span>
            <h2 class="grow">{#if n.name}<SafeText text={n.name} />{:else}{t('(a name received)')}{/if}</h2>
            {#if n.data}<span class="badge">#{n.data.seq_id}</span>{/if}
          </div>
          <div class="panel-body">
            <dl class="facts">
              <dt>{t('Id')}</dt><dd class="mono id"><span title={n.hash}>{n.hash.slice(0, 16)}…{n.hash.slice(-8)}</span> <CopyButton text={n.hash} /></dd>
              <dt>{t('Held at')}</dt><dd class="mono break">{n.address}</dd>
              {#each records(n.data) as [label, value] (label)}<dt>{t(label)}</dt><dd class="mono break"><SafeText text={value} /></dd>{/each}
              {#if records(n.data).length === 0}<dt>{t('Records')}</dt><dd class="muted">{t('none')}</dd>{/if}
            </dl>
          </div>
        </section>
      {/each}
    </div>
    {#if names?.registering?.length}
      <section class="panel">
        <div class="panel-head"><h2>{t('Registering: waiting for their block')}</h2></div>
        <div class="panel-body">
          {#each names.registering as p (p.hash)}
            <div class="row pend"><Icon name="clock" size={15} /><span class="grow"><SafeText text={p.name} /></span></div>
          {/each}
        </div>
      </section>
    {/if}
    {#if names?.pending?.length}
      <section class="panel">
        <div class="panel-head"><h2>{t('Reserved, waiting to be registered')}</h2></div>
        <div class="panel-body">
          {#each names.pending as p (p.hash)}
            <div class="row pend"><span class="grow"><SafeText text={p.name} /></span><button type="button" class="btn small" onclick={() => go('register' as never)}>{t('Register…')}</button></div>
          {/each}
        </div>
      </section>
    {/if}
  {/if}
</div>

<style>
  .mynames {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(22rem, 1fr));
    gap: 1rem;
  }
  .name h2 {
    margin: 0;
    font-size: 1.1rem;
  }
  .tagmark {
    color: var(--accent);
    display: grid;
  }
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.35rem 1rem;
    margin: 0;
    font-size: 0.9rem;
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
  .id {
    display: flex;
    align-items: center;
    gap: 0.35rem;
  }
  .empty .panel-body {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.5rem;
    color: var(--text-muted);
    padding: 2rem;
  }
  .pend {
    padding: 0.35rem 0;
  }
  .error {
    color: var(--negative);
  }
</style>
