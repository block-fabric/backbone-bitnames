// The three first steps of BitNames, on Home in Simple mode until dismissed.
import type { FirstStep } from '../lib/firststeps';

export const FIRST_STEPS: readonly FirstStep[] = [
  { title: 'Bring ECX here', text: 'Coins come from eCash. Drivechains gives a deposit address to pay from an eCash wallet (the Backbone app: Sidechains → BitNames). They arrive with the next block of BitNames.', icon: 'down', action: { label: 'Get a deposit address', page: 'peg', tab: 'deposit' } },
  { title: 'Get a name', text: 'A name is yours on BitNames: reserve it (hidden), then register it with what it points to.', icon: 'plus', action: { label: 'Get a name', page: 'register' as never } },
  { title: 'Look names up', text: 'The directory lists every name, and finds what any name points to.', icon: 'search', action: { label: 'Name directory', page: 'directory' as never } },
];
