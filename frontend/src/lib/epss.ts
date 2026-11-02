/** EPSS as a percentage: "0,4", "97" (the caller adds " %") – small values with one decimal. */
export function epssPercent(score: number, lang: string): string {
  const pct = score * 100
  return pct.toLocaleString(lang, { maximumFractionDigits: pct < 10 ? 1 : 0 })
}

/** The colour of an EPSS score: from 50 % critical, from 10 % high, from 1 % medium, below muted. */
export function epssTone(score: number): string {
  return score >= 0.5 ? "--sev-critical" : score >= 0.1 ? "--sev-high" : score >= 0.01 ? "--sev-medium" : "--muted-foreground"
}
