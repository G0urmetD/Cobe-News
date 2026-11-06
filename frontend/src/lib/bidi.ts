/**
 * Text people typed (names, labels) inside a sentence or a list: each part isolated, so a right-to-left name ("مركز
 * البيانات", "قاعدة") cannot pull the punctuation and numbers around it to its side ("1 · مركز البيانات Gerät" instead
 * of "مركز البيانات · 1 Gerät", 0.1.50). In JSX: <bdi>. Inside a translated sentence (a string): the Unicode isolates
 * FIRST STRONG ISOLATE … POP DIRECTIONAL ISOLATE – the same as <bdi>, for text.
 */
export const iso = (s: string | null | undefined): string => (s ? `⁨${s}⁩` : "")

/** Names as a list in a sentence – each one isolated. */
export const isoList = (names: (string | null | undefined)[], sep = ", "): string =>
  names
    .filter((n): n is string => !!n)
    .map(iso)
    .join(sep)
