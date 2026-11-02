/**
 * Browser and system of a session, read roughly from its User-Agent (no library): enough to tell "Firefox on Windows"
 * from "Safari on iPhone". null where it is not clear – the page then says "Unbekannt". The order matters: Edge and
 * Opera call themselves Chrome too, Chrome calls itself Safari, every iPhone browser is Safari underneath.
 */

export interface DeviceInfo {
  browser: string | null
  os: string | null
  mobile: boolean
}

const BROWSERS: [RegExp, string][] = [
  [/\bEdg(?:e|A|iOS)?\//, "Edge"],
  [/\b(?:OPR|Opera)\//, "Opera"],
  [/\bSamsungBrowser\//, "Samsung Internet"],
  [/\bVivaldi\//, "Vivaldi"],
  [/\b(?:Firefox|FxiOS)\//, "Firefox"],
  [/\b(?:Chrome|CriOS|Chromium)\//, "Chrome"],
  [/\bVersion\/[\d.]+.*\bSafari\//, "Safari"],
]

const SYSTEMS: [RegExp, string][] = [
  [/\biPhone\b/, "iPhone"],
  [/\biPad\b/, "iPad"],
  [/\bAndroid\b/, "Android"],
  [/\bCrOS\b/, "ChromeOS"],
  [/\bWindows\b/, "Windows"],
  [/\bMac OS X\b|\bMacintosh\b/, "macOS"],
  [/\bLinux\b/, "Linux"],
]

export function parseUserAgent(ua: string | null | undefined): DeviceInfo {
  const s = (ua ?? "").slice(0, 512)
  // a script or tool (curl, python-httpx …) – not a browser: neither is guessed
  if (!/^Mozilla\/5\.0 /.test(s)) return { browser: null, os: null, mobile: false }
  const browser = BROWSERS.find(([rx]) => rx.test(s))?.[1] ?? null
  const os = SYSTEMS.find(([rx]) => rx.test(s))?.[1] ?? null
  return { browser, os, mobile: /\bMobile\b|\biPhone\b|\bAndroid\b/.test(s) }
}
