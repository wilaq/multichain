import { useEffect, useRef, useState } from 'react';
import { formatMultibtc, parseMultibtc } from '../lib/format';

/**
 * Text inputs for amounts must hold the raw text the user typed.
 *
 * Deriving `value` from the stored number instead means React re-applies the
 * formatted number to the DOM on every change (react-dom `updateWrapper`:
 * `if (newValue !== node.value) node.value = newValue`). Typing "." does not
 * change the number, so the dot is deleted as it is typed and the next digit
 * lands in the integer part -- "1.5" silently becomes 15. That is a 10x error on
 * a figure signed under penalty of perjury, so these inputs keep their own text
 * state and only convert on the way out.
 */

const compact = (v: bigint) => (v === 0n ? '' : formatMultibtc(v, 8).replace(/\.?0+$/, ''));

export function AmountInput({
  value,
  onValue,
  placeholder,
  className = 'field-input',
}: {
  value: bigint;
  onValue: (v: bigint) => void;
  placeholder?: string;
  className?: string;
}) {
  const [text, setText] = useState(() => compact(value));
  // Tracks what we last emitted, so a value changed from the outside (e.g.
  // "Prefill from detected", or this row being reused for a different item after
  // a removal) re-seeds the text, while our own keystrokes do not.
  const lastEmitted = useRef(value);

  useEffect(() => {
    if (value !== lastEmitted.current) {
      lastEmitted.current = value;
      setText(compact(value));
    }
  }, [value]);

  return (
    <input
      className={className}
      inputMode="decimal"
      placeholder={placeholder}
      value={text}
      onChange={(e) => {
        const next = e.target.value;
        setText(next);
        let parsed: bigint;
        try {
          parsed = parseMultibtc(next);
        } catch {
          // parseMultibtc throws on things like "1.5 BTC"; keep the last good
          // number rather than crashing the form mid-keystroke.
          return;
        }
        lastEmitted.current = parsed;
        onValue(parsed);
      }}
      onBlur={() => setText(compact(lastEmitted.current))}
    />
  );
}

/** Same text-state treatment for the optional USD price, which must never store NaN. */
export function UsdInput({
  value,
  onValue,
  className = 'field-input',
}: {
  value: [] | [number];
  onValue: (v: [] | [number]) => void;
  className?: string;
}) {
  const [text, setText] = useState(() => (value.length > 0 ? String(value[0]) : ''));
  const lastEmitted = useRef(value);

  useEffect(() => {
    if (value !== lastEmitted.current) {
      lastEmitted.current = value;
      setText(value.length > 0 ? String(value[0]) : '');
    }
  }, [value]);

  return (
    <input
      className={className}
      inputMode="decimal"
      value={text}
      onChange={(e) => {
        const next = e.target.value;
        setText(next);
        const t = next.trim();
        if (t === '') {
          const empty: [] = [];
          lastEmitted.current = empty;
          onValue(empty);
          return;
        }
        const n = Number(t);
        if (!Number.isFinite(n)) return; // never store NaN
        const wrapped: [number] = [n];
        lastEmitted.current = wrapped;
        onValue(wrapped);
      }}
    />
  );
}
