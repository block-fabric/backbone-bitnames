// BitNames' own pages beside the drop-in pages (chain/overrides.ts puts those in the kit's places): getting a name
// (reserved, then registered), the wallet's names, and the directory of every name with a look-up.
import type { IconName } from '../components/Icon.svelte';

export interface LocalPage {
  id: string;
  title: string;
  icon: IconName;
  summary: string;
  section: 'wallet' | 'chain' | 'tools';
  wallet?: boolean;
  shortcut?: string;
  keywords?: string;
  quick?: { label: string; icon?: IconName; tab?: string; simpleLabel?: string };
  simpleTitle?: string;
  advanced?: boolean;
  simple?: boolean;
  simpleSummary?: string;
  tabOf?: { page: string; tab: string };
}

export const LOCAL_PAGES = [
  { id: 'register', title: 'Get a name', simple: true, simpleSummary: 'Find a free name and make it yours', icon: 'tagplus', section: 'chain', summary: 'Find a name that is free and take it: reserved, then registered', keywords: 'bitnames register reserve search available claim', quick: { label: 'Get a name', icon: 'tagplus' } },
  { id: 'names', title: 'My names', simple: true, simpleSummary: 'The names you own', icon: 'tag', section: 'chain', shortcut: 'Alt+6', summary: 'The names of the wallet, their records, and reservations waiting to be registered', keywords: 'bitnames names records owned' },
  { id: 'directory', title: 'Name directory', icon: 'atlas', section: 'chain', summary: 'Every name of the registry, and a look-up of any name', keywords: 'bitnames lookup resolve whois registry search' },
] as const satisfies readonly LocalPage[];

export type LocalPageId = (typeof LOCAL_PAGES)[number]['id'];

export interface LocalCommand {
  id: string;
  label: string;
  page: LocalPageId;
  tab?: string;
  tip?: string;
  keywords?: string;
}

export const LOCAL_COMMANDS = [
  { id: 'bn.lookup', label: 'Look up a name…', page: 'directory', tip: 'What a name points to, registered or not', keywords: 'resolve lookup whois' },
] as const satisfies readonly LocalCommand[];
