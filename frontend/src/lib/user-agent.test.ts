import { describe, expect, it } from "vitest"
import { parseUserAgent } from "@/lib/user-agent"

const UA = {
  chromeWin: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
  edgeWin: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
  firefoxLinux: "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
  safariMac: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
  safariIphone: "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
  chromeIphone: "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0 Mobile/15E148 Safari/604.1",
  chromeAndroid: "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
  operaMac: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 OPR/124.0.0.0",
  chromeOs: "Mozilla/5.0 (X11; CrOS x86_64 16000.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
}

describe("parseUserAgent", () => {
  it("tells the usual browsers and systems apart", () => {
    expect(parseUserAgent(UA.chromeWin)).toEqual({ browser: "Chrome", os: "Windows", mobile: false })
    expect(parseUserAgent(UA.edgeWin)).toMatchObject({ browser: "Edge", os: "Windows" })
    expect(parseUserAgent(UA.firefoxLinux)).toMatchObject({ browser: "Firefox", os: "Linux" })
    expect(parseUserAgent(UA.safariMac)).toMatchObject({ browser: "Safari", os: "macOS" })
    expect(parseUserAgent(UA.safariIphone)).toEqual({ browser: "Safari", os: "iPhone", mobile: true })
    expect(parseUserAgent(UA.chromeIphone)).toMatchObject({ browser: "Chrome", os: "iPhone" })
    expect(parseUserAgent(UA.chromeAndroid)).toEqual({ browser: "Chrome", os: "Android", mobile: true })
    expect(parseUserAgent(UA.operaMac)).toMatchObject({ browser: "Opera", os: "macOS" })
    expect(parseUserAgent(UA.chromeOs)).toMatchObject({ browser: "Chrome", os: "ChromeOS" })
  })

  it("guesses nothing when it is not clear", () => {
    expect(parseUserAgent("")).toEqual({ browser: null, os: null, mobile: false })
    expect(parseUserAgent(null)).toEqual({ browser: null, os: null, mobile: false })
    expect(parseUserAgent("curl/8.9.1")).toEqual({ browser: null, os: null, mobile: false })
    expect(parseUserAgent("pytest")).toEqual({ browser: null, os: null, mobile: false })
    expect(parseUserAgent("Mozilla/5.0 (compatible; SomeBot/1.0)")).toEqual({ browser: null, os: null, mobile: false })
  })
})
