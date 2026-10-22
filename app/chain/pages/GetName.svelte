<script lang="ts">
  // Get a name: is it free? Reserve it (only its commitment goes on the chain, so nobody can take it first once they see
  // it), then, once the reservation is in a block, register it with what it points to. Each step asked in the app's
  // trusted dialog (reserve_bitname, register_bitname).
  import SafeText from '../../components/SafeText.svelte';
  import Icon from '../../components/Icon.svelte';
  import { declined, errorText } from '../../lib/dialogs.svelte';
  import { t } from '../../lib/i18n.svelte';
    import { toast } from '../../lib/state.svelte';
  import SetupWallet from '../dropin/SetupWallet.svelte';
  import { confirmed } from '../dropin/api';
  import { drop, follow, refresh } from '../dropin/store.svelte';
  import { bn, nameProblem, type Names, type Resolved } from '../bn';

  $effect(() => follow());

  let name = $state('');
  let checked = $state<Resolved | null>(null);
  let busy = $state(false);
  let error = $state('');
  let names = $state<Names | null>(null);
  /** Names this page reserved (their reservation not in a block yet). */
  let reservedHere = $state<string[]>([]);
  let ipv4 = $state('');
  let paymailFee = $state('');

  const problem = $derived(nameProblem(name));
  const pending = $derived(names?.pending ?? []);
  const has = (list: { hash: string }[] | undefined, hash: string) => !!list?.some((n) => n.hash === hash);
  /** Where this name is: free; reserved here (its reservation waiting for a block); ready to register; registering
   *  (waiting for its block); yours; or taken. */
  const step = $derived.by(() => {
    if (!checked || checked.name !== name) return 'type';
    if (checked.registered) return has(names?.owned, checked.hash) ? 'yours' : 'taken';
    if (has(names?.registering, checked.hash)) return 'registering';
    if (has(pending, checked.hash)) return 'register';
    if (reservedHere.includes(name)) return 'waiting';
    return 'free';
  });

  // The wallet's names and the name typed, looked up again at each new block (a reservation or a registration in it).
  $effect(() => {
    void drop.version;
    bn.names()
      .then((n) => (names = n))
      .catch(() => (names = null));
  });
  $effect(() => {
    const text = name;
    void drop.version;
    if (nameProblem(text)) {
      checked = null;
      return;
    }
    const timer = setTimeout(() => {
      bn.resolve(text)
        .then((r) => {
          if (text === name) checked = r;
        })
        .catch((e) => (error = errorText(e)));
    }, 250);
    return () => clearTimeout(timer);
  });

  async function reserve() {
    busy = true;
    error = '';
    try {
      await confirmed<string>('reserve_bitname', [name]);
      reservedHere = [...reservedHere, name];
      toast('success', t('Reserved'), t('Register %1 once the reservation is in a block (the next block of BitNames).', name));
      await refresh();
    } catch (e) {
      if (!declined(e)) error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function register() {
    busy = true;
    error = '';
    try {
      const data: Record<string, unknown> = {};
      if (ipv4.trim()) data.socket_addr_v4 = ipv4.trim();
      if (paymailFee.trim()) data.paymail_fee_sats = Number(paymailFee.trim());
      await confirmed<string>('register_bitname', Object.keys(data).length ? [name, data] : [name]);
      toast('success', t('Registration sent'), t('%1 is yours once the registration is in a block.', name));
      await refresh();
      names = await bn.names();
    } catch (e) {
      if (!declined(e)) error = errorText(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="page getname">
  <header class="page-head"><h1>{t('Get a name')}</h1></header>
  {#if drop.seed && !drop.seed.hasSeed}
    <SetupWallet compact />
  {:else}
    <section class="panel search">
      <div class="panel-body">
        <label for="bn-name" class="big-label">{t('Which name?')}</label>
        <input id="bn-name" type="text" class="big" placeholder={t('a name')} spellcheck="false" autocomplete="off" bind:value={name} />
        <div class="verdict">
          {#if !name}<span class="muted">{t('Any text: a name is unique on BitNames, once registered.')}</span>
          {:else if problem}<span class="bad"><Icon name="alert" size={15} /> {t(problem)}</span>
          {:else if step === 'type'}<span class="muted">{t('Looking it up…')}</span>
          {:else if step === 'free'}<span class="good"><Icon name="check" size={15} /> {t('Free: you can have it')}</span>
          {:else if step === 'waiting'}<span class="warn"><Icon name="clock" size={15} /> {t('Reserved: waiting for its block, then register it here')}</span>
          {:else if step === 'register'}<span class="good"><Icon name="check" size={15} /> {t('Your reservation is in a block: register it now')}</span>
          {:else if step === 'registering'}<span class="warn"><Icon name="clock" size={15} /> {t('Registered: waiting for its block')}</span>
          {:else if step === 'yours'}<span class="good"><Icon name="check" size={15} /> {t('Yours already')}</span>
          {:else}<span class="bad"><Icon name="x" size={15} /> {t('Taken')}</span>{/if}
        </div>
      </div>
    </section>

    <div class="steps">
      <section class="panel step" class:current={step === 'free'} class:done={step === 'waiting' || step === 'register' || step === 'registering' || step === 'yours'}>
        <div class="panel-body">
          <span class="num-badge">1</span>
          <h2>{t('Reserve it')}</h2>
          <p class="muted">{t('Only a commitment to the name goes on the chain: nobody learns it, so nobody can take it before you.')}</p>
          <button type="button" class="btn primary" disabled={busy || step !== 'free'} onclick={reserve}><Icon name="lock" size={15} /> {t('Reserve…')}</button>
        </div>
      </section>
      <section class="panel step" class:current={step === 'register'} class:done={step === 'registering' || step === 'yours'}>
        <div class="panel-body">
          <span class="num-badge">2</span>
          <h2>{t('Register it')}</h2>
          <p class="muted">{t('Reveals the name and makes it yours, with what it points to (all optional).')}</p>
          <div class="field">
            <label for="bn-ipv4">{t('IPv4 address and port')}</label>
            <input id="bn-ipv4" type="text" class="mono" placeholder="203.0.113.7:443" bind:value={ipv4} />
          </div>
          <div class="field">
            <label for="bn-fee">{t('Paymail fee (sat)')}</label>
            <input id="bn-fee" type="number" min="0" bind:value={paymailFee} />
          </div>
          <button type="button" class="btn primary" disabled={busy || step !== 'register'} onclick={register}><Icon name="check" size={15} /> {t('Register…')}</button>
        </div>
      </section>
    </div>
    {#if pending.length && step !== 'register'}
      <section class="panel">
        <div class="panel-head"><h2>{t('Reserved, waiting to be registered')}</h2></div>
        <div class="panel-body list">
          {#each pending as p (p.hash)}
            <button type="button" class="link" onclick={() => (name = p.name)}><SafeText text={p.name} /></button>
          {/each}
        </div>
      </section>
    {/if}
    {#if error}<p class="error"><Icon name="alert" size={14} /> {error}</p>{/if}
  {/if}
</div>

<style>
  .getname {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .search .panel-body {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .big-label {
    font-weight: 600;
  }
  input.big {
    font-size: 1.35rem;
    padding: 0.7rem 0.9rem;
  }
  .verdict {
    min-height: 1.5rem;
    display: flex;
    align-items: center;
  }
  .verdict span {
    display: inline-flex;
    gap: 0.35rem;
    align-items: center;
  }
  .good {
    color: var(--positive);
  }
  .bad {
    color: var(--negative);
  }
  .warn {
    color: var(--warning);
  }
  .steps {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr));
    gap: 1rem;
  }
  .step .panel-body {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
    align-items: flex-start;
  }
  .step h2 {
    margin: 0;
    font-size: 1.05rem;
  }
  .step p {
    margin: 0;
  }
  .step.current {
    border-color: color-mix(in srgb, var(--accent) 55%, var(--border));
  }
  .step.done {
    opacity: 0.75;
  }
  .num-badge {
    display: grid;
    place-items: center;
    width: 1.8rem;
    height: 1.8rem;
    border-radius: 50%;
    background: color-mix(in srgb, var(--accent) 18%, transparent);
    color: var(--accent);
    font-weight: 700;
  }
  .step .field {
    width: 100%;
  }
  .list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.6rem;
  }
  .link {
    background: none;
    border: none;
    color: var(--accent);
    cursor: pointer;
    padding: 0;
  }
  .error {
    color: var(--negative);
  }
</style>
