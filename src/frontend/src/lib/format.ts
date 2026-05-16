// multiBTC has 8 decimals, identical to BTC.
export const MULTIBTC_SCALE = 100_000_000n;

export function formatMultibtc(raw: bigint, decimals = 6): string {
  const sign = raw < 0n ? '-' : '';
  const abs = raw < 0n ? -raw : raw;
  const whole = abs / MULTIBTC_SCALE;
  const frac = abs % MULTIBTC_SCALE;
  const fracStr = frac.toString().padStart(8, '0').slice(0, decimals);
  return `${sign}${whole.toString()}.${fracStr}`;
}

export function parseMultibtc(text: string): bigint {
  const t = text.trim();
  if (t.length === 0) return 0n;
  const [whole, frac = ''] = t.split('.');
  const wholeBI = BigInt(whole.replace(/[^0-9-]/g, '') || '0');
  const fracPadded = (frac + '00000000').slice(0, 8);
  const fracBI = BigInt(fracPadded);
  const sign = whole.trim().startsWith('-') ? -1n : 1n;
  return sign * (wholeBI * MULTIBTC_SCALE + (sign < 0n ? -fracBI : fracBI));
}

export function shortAddress(a: string): string {
  if (!a) return '';
  const lower = a.toLowerCase();
  return `${lower.slice(0, 6)}…${lower.slice(-4)}`;
}

export function formatTsNs(ns: bigint | number): string {
  const ms = typeof ns === 'bigint' ? Number(ns / 1_000_000n) : Math.floor(ns / 1_000_000);
  return new Date(ms).toISOString();
}
