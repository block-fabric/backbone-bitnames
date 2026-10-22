// The end-to-end run of bitnames-app on a local eCash regtest (run_app.py): the app starts and runs its node; the
// wallet's backup phrase is made (its words only in the trusted dialog); ECX is deposited from eCash through the
// mainchain interface's wallet; a payment is sent to another BitNames node and one received from it; a name is
// reserved, registered with a record and looked up (node B resolves it too); a withdrawal to eCash goes through a
// bundle and is paid; every page is pictured, in the dark and the light theme.
// window.__E2E: { peerAddress, mainAddress } from the runner.
(async () => {
  const { host, sleep, log, T, waitFor, check, snapshot, click, type, go, theme, finish, ready } = E2E;
  const overview = () => host('dropin.overview');
  const history = () => host('dropin.history', { limit: 50 });
  const ecx = 100_000_000;
  try {
    await ready();
    await check('the app runs its node (phase ready, a tip)', T().app.phase === 'ready');
    await check('app.info is the node’s and the app’s', T().app.info.name === 'BitNames' && T().app.info.hostApi === 1 && T().app.info.embedded === false);
    await go('home');
    await waitFor('the setup card', () => document.querySelector('.setup'));
    await snapshot('bitnames-01-first-start');

    // ---- the backup phrase: made by the node, shown in the trusted dialog (answered yes by the test), the wallet set
    await host('test.confirmAnswer', { yes: true });
    await click('Make a new backup phrase');
    await waitFor('the wallet set up', async () => (await host('dropin.seed.status')).hasSeed);
    const asked = await host('test.confirmed');
    const phraseQ = asked.find((q) => q.kind === 'node:phrase.create');
    await check('the phrase was asked in the trusted dialog, its words never recorded', !!phraseQ && phraseQ.details === '(the words, not recorded)');
    await check('the page got no words', !JSON.stringify(T().app).match(/\b(abandon|zoo)\b/));
    await go('home');
    await waitFor('the home with a wallet', () => !document.querySelector('.setup'));
    await snapshot('bitnames-02-wallet-ready');

    // ---- a deposit from eCash, paid by Backbone's wallet (-grpcwallet), confirmed in the trusted dialog
    await go('peg', 'deposit');
    await waitFor('the deposit form', () => document.querySelector('#dep-amount'));
    await snapshot('bitnames-03-deposit');
    type('#dep-amount', '10');
    await host('test.confirmAnswer', { yes: true });
    await click('Review and deposit');
    await log('SIGNAL deposit-sent');
    await waitFor('the deposit credited', async () => (await overview()).wallet.available >= 10 * ecx, 300000);
    const deposited = (await history()).find((r) => r.kind === 'deposit');
    await check('the deposit is in the activity', !!deposited && deposited.amount === 10 * ecx, JSON.stringify(deposited));
    const q1 = (await host('test.confirmed')).find((q) => q.kind === 'node:deposit');
    await check('the deposit was asked with its amount and its address', !!q1 && q1.rows.some((r) => r.label === 'Amount' && r.value === '10.00000000 ECX'));

    // ---- send to the other BitNames node
    await go('send');
    type('#send-to', window.__E2E.peerAddress);
    await waitFor('the address checked', () => document.querySelector('.state.good'));
    type('#send-amount', '1.5');
    await snapshot('bitnames-04-send');
    await host('test.confirmAnswer', { yes: true });
    await click('Review and send');
    await waitFor('the payment sent', async () => (await history()).some((r) => r.kind === 'send'), 60000);
    const q2 = (await host('test.confirmed')).find((q) => q.kind === 'node:send');
    await check('the payment was asked with the recipient first', !!q2 && q2.rows[0].label === 'To' && q2.rows[0].value === window.__E2E.peerAddress);
    await waitFor('the payment in a block', async () => (await history()).some((r) => r.kind === 'send' && !r.pending), 300000);
    await log('SIGNAL sent');

    // ---- receive from it
    await go('receive');
    const shown = await waitFor('an address shown', () => {
      const el = document.querySelector('.addr .mono.big');
      return el ? el.textContent.trim() : null;
    });
    await snapshot('bitnames-05-receive');
    await log(`SIGNAL receive-address ${shown}`);
    await waitFor('the payment received', async () => (await history()).some((r) => r.kind === 'receive' && !r.pending && r.amount === 0.25 * ecx), 300000);
    await check('a payment received at the address shown', true);
    await go('transactions');
    await sleep(1500);
    await snapshot('bitnames-06-activity');

    // ---- a name: free, reserved (asked), its reservation in a block, registered with a record (asked), looked up
    const NAME = 'backbone-e2e';
    await go('register');
    type('#bn-name', NAME);
    await waitFor('the name free', () => document.querySelector('.verdict .good'), 30000);
    await snapshot('bitnames-11-name-free');
    await host('test.confirmAnswer', { yes: true });
    await click('Reserve…');
    await waitFor('the reservation asked', async () => (await host('test.confirmed')).some((q) => q.kind === 'node:name.reserve'));
    const qr = (await host('test.confirmed')).find((q) => q.kind === 'node:name.reserve');
    await check('the reservation was asked with the name', !!qr && qr.rows.some((r) => r.label === 'Name' && r.value === NAME));
    await waitFor('the reservation in a block', async () => (await host('bitnames.names')).pending.some((p) => p.name === NAME), 300000);
    await waitFor('the register step', () => {
      const b = [...document.querySelectorAll('button')].find((x) => x.textContent.trim().startsWith('Register…'));
      return b && !b.disabled;
    }, 30000);
    type('#bn-ipv4', '203.0.113.7:443');
    await snapshot('bitnames-12-register');
    await host('test.confirmAnswer', { yes: true });
    await click('Register…');
    await waitFor('the registration asked', async () => (await host('test.confirmed')).some((q) => q.kind === 'node:name.register'));
    const qg = (await host('test.confirmed')).find((q) => q.kind === 'node:name.register');
    await check('the registration was asked with its record', !!qg && qg.rows.some((r) => r.label === "IPv4 address" && r.value === "203.0.113.7:443"));
    const owned = await waitFor('the name owned', async () => (await host('bitnames.names')).owned.find((n) => n.name === NAME), 300000);
    await check('the name is the wallet’s, with its record', owned.data && owned.data.socket_addr_v4 === '203.0.113.7:443', JSON.stringify(owned));
    await log(`SIGNAL registered ${owned.hash} 203.0.113.7:443`);
    const resolved = await host('bitnames.resolve', { name: NAME });
    await check('the name resolves to its record', resolved.registered && resolved.hash === owned.hash && resolved.data.socket_addr_v4 === '203.0.113.7:443');
    await go('names');
    await sleep(1200);
    await snapshot('bitnames-13-my-names');
    await go('directory');
    type('input[type="search"]', NAME);
    document.querySelector('.lookup').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await waitFor('the name found in the directory', () => document.querySelector('.found dl'), 30000);
    await sleep(800);
    await snapshot('bitnames-14-directory');
    const free = await host('bitnames.resolve', { name: 'nobody-has-this-name' });
    await check('a name nobody registered is free', free.registered === false);

    // ---- withdraw to eCash: a bundle, voted, paid
    await go('peg', 'withdraw');
    type('#w-to', window.__E2E.mainAddress);
    await waitFor('the eCash address checked', () => document.querySelector('.state.good'));
    type('#w-amount', '2');
    await snapshot('bitnames-07-withdraw');
    await host('test.confirmAnswer', { yes: true });
    await click('Review and withdraw');
    await waitFor('the withdrawal asked', async () => (await host('dropin.peg')).withdrawals.length > 0, 60000);
    await log('SIGNAL withdrawal-asked');
    await go('peg', 'bundles');
    await sleep(1500);
    await snapshot('bitnames-08-bundle');
    const paid = await waitFor('the withdrawal paid on eCash', async () => (await host('dropin.peg')).withdrawals.find((w) => w.state === 'paid'), 900000);
    await check('the withdrawal is paid on eCash', !!paid, JSON.stringify(paid));
    await log(`SIGNAL withdrawal-paid ${paid.m6id}`);
    await go('peg', 'bundles');
    await sleep(1500);
    await snapshot('bitnames-09-paid');

    // ---- the other pages, both themes
    for (const [mode, id] of [['dark', 'midnight'], ['light', 'light']]) {
      await theme(id);
      for (const [page, tab, name] of [['home', '', 'home'], ['overview', '', 'overview'], ['transactions', '', 'activity'], ['explorer', '', 'explorer'], ['node', 'info', 'node'], ['node', 'peers', 'peers'], ['register', '', 'get-name'], ['names', '', 'my-names'], ['directory', '', 'directory'], ['settings', 'dropnode', 'settings-node'], ['settings', 'dropwallet', 'settings-wallet']]) {
        await go(page, tab);
        await sleep(1200);
        await snapshot(`bitnames-${mode}-${name}`);
      }
    }
    await theme('midnight');

    // ---- the explorer: a block's details
    await go('explorer');
    await waitFor('blocks listed', () => document.querySelectorAll('[role="row"]').length > 2, 30000);
    const first = document.querySelector('[role="row"]:nth-child(2)') || document.querySelectorAll('[role="row"]')[1];
    if (first) first.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }));
    await sleep(1500);
    await snapshot('bitnames-10-block');

    // ---- the backup phrase shown again: a question of the trusted dialog, never words in the page
    await go('settings', 'dropwallet');
    await host('test.confirmAnswer', { yes: true });
    await click('Show the phrase');
    await sleep(1000);
    const shownQ = (await host('test.confirmed')).filter((q) => q.kind === 'node:phrase.show');
    await check('showing the phrase is a question of the trusted dialog', shownQ.length === 1);

    // ---- saved to a file the user chose: asked, then written (the runner checks the file: owner-only, the words)
    await host('test.fileAnswer', { path: window.__E2E.saveFile });
    await host('test.confirmAnswer', { yes: true });
    await click('Save it to a file');
    await waitFor('the phrase saved', async () => (await host('test.confirmed')).some((q) => q.kind === 'node:phrase.save'), 30000);
    await sleep(1500);
    await log(`SIGNAL phrase-saved ${window.__E2E.saveFile}`);
  } catch (e) {
    await check('the run', false, e && e.stack ? e.stack : String(e));
  }
  await finish();
})();
