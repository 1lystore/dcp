/**
 * Small string-safety helpers for the relay's public HTTP surface.
 */

/**
 * Strip trailing '/' characters without a backtracking regex.
 *
 * Replaces `s.replace(/\/+$/, '')`, which CodeQL flags as polynomial-ReDoS on
 * inputs with many '/'. This is a simple linear scan.
 */
export function stripTrailingSlashes(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 47 /* '/' */) end--;
  return s.slice(0, end);
}

/**
 * Serialize a value for safe embedding inside an inline <script>...</script>.
 *
 * JSON.stringify alone is NOT safe in a script context: a value containing
 * `</script>` can break out of the tag and inject markup. Escaping `<`, `>` and
 * `&` to their \uXXXX forms keeps the payload a valid JS string while making
 * tag-breakout impossible.
 */
export function jsonForScript(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026');
}
