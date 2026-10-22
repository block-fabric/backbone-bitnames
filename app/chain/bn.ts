// BitNames' own host methods (bitnames.*): the wallet's names, a name looked up, the directory.
import { request } from '../lib/bridge';

/** A name's records as the node says them (bitname_data: seq_id, then each record or null). */
export interface NameData {
  seq_id: string;
  commitment: number[] | null;
  socket_addr_v4: string | null;
  socket_addr_v6: string | null;
  encryption_pubkey: string | null;
  signing_pubkey: string | null;
  paymail_fee_sats: number | null;
}

export interface OwnedName {
  hash: string;
  name?: string;
  address: string;
  data?: NameData;
}

export interface Names {
  owned: OwnedName[];
  reservations: { txid: string; commitment: string; address: string }[];
  /** Reserved by this wallet (the reservation in a block), not registered yet: the next step. */
  pending?: { name: string; hash: string }[];
  /** Their registration sent, waiting for its block. */
  registering?: { name: string; hash: string }[];
}

export interface Resolved {
  name: string;
  hash: string;
  registered: boolean;
  data?: NameData;
}

const host = <T>(method: string, params: Record<string, unknown> = {}) => request<T>('host', method, params);

export const bn = {
  names: () => host<Names>('bitnames.names'),
  resolve: (name: string) => host<Resolved>('bitnames.resolve', { name }),
  directory: (limit = 1000) => host<{ hash: string; name?: string; data: NameData }[]>('bitnames.directory', { limit }),
};

/** The records of a name to show: label, value. */
export function records(d: NameData | undefined): [string, string][] {
  if (!d) return [];
  const out: [string, string][] = [];
  if (d.socket_addr_v4) out.push(['IPv4', d.socket_addr_v4]);
  if (d.socket_addr_v6) out.push(['IPv6', d.socket_addr_v6]);
  if (d.encryption_pubkey) out.push(['Encryption key', d.encryption_pubkey]);
  if (d.signing_pubkey) out.push(['Signing key', d.signing_pubkey]);
  if (d.paymail_fee_sats !== null && d.paymail_fee_sats !== undefined) out.push(['Paymail fee', `${d.paymail_fee_sats} sat`]);
  if (d.commitment) out.push(['Commitment', d.commitment.map((b) => b.toString(16).padStart(2, '0')).join('')]);
  return out;
}

/** What a name may be (their rules take any UTF-8 text; ours keep it to one line, at most 255 bytes). */
export function nameProblem(name: string): string {
  if (!name) return 'Type a name';
  if (new TextEncoder().encode(name).length > 255) return 'At most 255 bytes';
  if (/[\u0000-\u001f\u007f]/.test(name)) return 'No control characters';
  if (name !== name.trim()) return 'No spaces around it';
  return '';
}
