// Icons of BitNames' own pages (components/Icon.svelte): line icons on a 24 grid.
export const LOCAL_ICONS = {
  /** A name: a tag with its hole. */
  tag: 'M3.5 6.5a2 2 0 0 1 2-2h8.2a2 2 0 0 1 1.4.6l5.4 5.5a2 2 0 0 1 0 2.8l-5.4 5.5a2 2 0 0 1-1.4.6H5.5a2 2 0 0 1-2-2zM8 12a1.4 1.4 0 1 0 2.8 0A1.4 1.4 0 1 0 8 12',
  /** Get a name: a tag and a plus. */
  tagplus: 'M3.5 6.5a2 2 0 0 1 2-2h8.2a2 2 0 0 1 1.4.6l5.4 5.5a2 2 0 0 1 0 2.8l-5.4 5.5a2 2 0 0 1-1.4.6H5.5a2 2 0 0 1-2-2zM7 12h6M10 9v6',
  /** The directory: an open book. */
  atlas: 'M4 5.5C6.5 4.5 9.5 4.5 12 6c2.5-1.5 5.5-1.5 8-.5v13c-2.5-1-5.5-1-8 .5-2.5-1.5-5.5-1.5-8-.5zM12 6v13.5',
} as const satisfies Record<string, string>;
