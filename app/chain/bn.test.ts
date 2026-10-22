// BitNames' own pages over a pretend node: a name reserved then registered only through rpc.confirmed with the LayerTwo
// parameters (reserve_bitname [name], register_bitname [name, records]), the steps from what the node says, and no
// request outside the manifest.
import { fireEvent, render, waitFor } from '@testing-library/svelte';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { setTransport, type BridgeRequest } from '../lib/bridge';
import { nameProblem, records } from './bn';

const manifest = JSON.parse(readFileSync(join(__dirname, 'manifest.json'), 'utf8')) as { reads: string[]; confirmed: string[]; host: string[] };
const APP_METHODS = new Set(['app.hello', 'app.info', 'app.locale', 'app.languages', 'prefs.get', 'prefs.set', 'node.state', 'rpc.confirmed', 'rpc.confirmedMethods', 'window.state', 'clipboard.write', 'app.notify']);
const HASH = 'ab'.repeat(32);

let calls: BridgeRequest[] = [];
let answers: Record<string, (r: BridgeRequest) => unknown> = {};
let names = { owned: [] as unknown[], reservations: [] as unknown[], pending: [] as unknown[], registering: [] as unknown[] };

beforeEach(() => {
  calls = [];
  names = { owned: [], reservations: [], pending: [], registering: [] };
  answers = {
    'dropin.overview': () => ({ wallet: { hasSeed: true, available: 250_000_000, withdrawing: 0, pendingIn: 0, pendingOut: 0 }, chain: { height: 5, peers: 0, slot: 2 }, mainchain: { slot: 2, connected: true, state: 'ok' } }),
    'dropin.seed.status': () => ({ hasSeed: true, phraseKept: true, from: 'app', fingerprint: '00', derivation: 'plain_bitnames' }),
    'bitnames.names': () => names,
    'bitnames.resolve': (r) => ({ name: (r.params as { name: string }).name, hash: HASH, registered: false }),
    'bitnames.directory': () => [{ hash: HASH, data: { seq_id: '1', commitment: null, socket_addr_v4: '203.0.113.7:443', socket_addr_v6: null, encryption_pubkey: null, signing_pubkey: null, paymail_fee_sats: null } }],
    'rpc.confirmed': () => 'cd'.repeat(32),
  };
  setTransport(async (req) => {
    calls.push(req);
    const answer = answers[req.kind === 'host' ? (req.method ?? '') : `rpc:${req.method}`];
    return answer ? answer(req) : null;
  });
});
afterEach(() => setTransport(null));

const confirmedCalls = () => calls.filter((c) => c.kind === 'host' && c.method === 'rpc.confirmed').map((c) => c.params as { method: string; params: unknown[] });

describe('BitNames pages', () => {
  it('a free name is reserved with reserve_bitname [name], then registered with its records once the reservation is in a block', async () => {
    const { refresh } = await import('./dropin/store.svelte');
    await refresh();
    const GetName = (await import('./pages/GetName.svelte')).default;
    const { container, getByLabelText } = render(GetName);
    await fireEvent.input(getByLabelText('Which name?'), { target: { value: 'backbone' } });
    await waitFor(() => expect(container.querySelector('.verdict .good')).toBeTruthy(), { timeout: 3000 });
    const reserve = [...container.querySelectorAll('button')].find((b) => b.textContent?.includes('Reserve')) as HTMLButtonElement;
    expect(reserve.disabled).toBe(false);
    await fireEvent.click(reserve);
    await waitFor(() => expect(confirmedCalls()).toEqual([{ method: 'reserve_bitname', params: ['backbone'] }]));
    // The reservation in a block: the node says the name is pending; the page offers to register it.
    names = { ...names, pending: [{ name: 'backbone', hash: HASH }] };
    const { drop } = await import('./dropin/store.svelte');
    drop.version++;
    const register = () => [...container.querySelectorAll('button')].find((b) => b.textContent?.includes('Register')) as HTMLButtonElement;
    await waitFor(() => expect(register().disabled).toBe(false), { timeout: 3000 });
    await fireEvent.input(container.querySelector('#bn-ipv4') as HTMLInputElement, { target: { value: '203.0.113.7:443' } });
    await fireEvent.click(register());
    await waitFor(() => expect(confirmedCalls().length).toBe(2));
    expect(confirmedCalls()[1]).toEqual({ method: 'register_bitname', params: ['backbone', { socket_addr_v4: '203.0.113.7:443' }] });
  });

  it('a name with no records is registered with [name] only; a taken name offers nothing', async () => {
    answers['bitnames.resolve'] = (r) => ({ name: (r.params as { name: string }).name, hash: HASH, registered: true, data: { seq_id: '1' } });
    const GetName = (await import('./pages/GetName.svelte')).default;
    const { container, getByLabelText } = render(GetName);
    await fireEvent.input(getByLabelText('Which name?'), { target: { value: 'taken' } });
    await waitFor(() => expect(container.querySelector('.verdict .bad')).toBeTruthy(), { timeout: 3000 });
    for (const b of container.querySelectorAll('.step button')) expect((b as HTMLButtonElement).disabled).toBe(true);
    expect(confirmedCalls()).toEqual([]);
  });

  it('call nothing of the node outside the manifest', async () => {
    for (const page of ['GetName', 'MyNames', 'Directory']) render((await import(`./pages/${page}.svelte`)).default);
    render((await import('./LocalCards.svelte')).default);
    await new Promise((r) => setTimeout(r, 400));
    const allowed = new Set([...manifest.host, ...APP_METHODS]);
    const bad = calls.filter((c) => (c.kind === 'host' ? !allowed.has(c.method ?? '') : !manifest.reads.includes(c.method ?? '')));
    expect(bad.map((c) => `${c.kind}:${c.method}`)).toEqual([]);
  });

  it('names and records in words', () => {
    expect(nameProblem('')).toBe('Type a name');
    expect(nameProblem(' a')).toBe('No spaces around it');
    expect(nameProblem('a\nb')).toBe('No control characters');
    expect(nameProblem('a\u202eb')).toBe('No invisible or direction marks');
    expect(nameProblem('a\u200bb')).toBe('No invisible or direction marks');
    expect(nameProblem('é'.repeat(128))).toBe('At most 255 bytes');
    expect(nameProblem('backbone')).toBe('');
    expect(records({ seq_id: '1', commitment: [1, 255], socket_addr_v4: '1.2.3.4:5', socket_addr_v6: null, encryption_pubkey: null, signing_pubkey: null, paymail_fee_sats: 0 })).toEqual([
      ['IPv4', '1.2.3.4:5'],
      ['Paymail fee', '0 sat'],
      ['Commitment', '01ff'],
    ]);
  });
});
