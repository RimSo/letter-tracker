export const STATUSES = [
  'Active',
  'Delivered',
  'Draft',
  'Returned',
  'Lost'
] as const;

export type LetterStatus = typeof STATUSES[number];
