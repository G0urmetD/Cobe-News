import { describe, expect, it } from "vitest"
import de from "@/i18n/de"
import en from "@/i18n/en"
import { backupErrorKey, backupState, fmtBytes, removedBy, restoreCommand, STATE_COLOR } from "@/lib/backup"

describe("fmtBytes", () => {
  it("uses decimal units and the reader's separator", () => {
    expect(fmtBytes(0, "de")).toBe("0 B")
    expect(fmtBytes(999, "de")).toBe("999 B")
    expect(fmtBytes(61_440, "de")).toBe("61,4 kB")
    expect(fmtBytes(61_440, "en")).toBe("61.4 kB")
    expect(fmtBytes(20_819_968, "de")).toBe("20,8 MB")
    expect(fmtBytes(250_000_000, "en")).toBe("250 MB")
    expect(fmtBytes(-5, "en")).toBe("0 B")
  })
})

describe("backupState", () => {
  const now = Date.parse("2026-10-29T12:00:00Z")
  it("tells none, failed, stale and ok apart", () => {
    expect(backupState(null, now)).toBe("none")
    expect(backupState({ ok: false, at: "2026-10-29T11:00:00Z", error: "pg_dump failed" }, now)).toBe("failed")
    expect(backupState({ ok: true, at: "2026-10-21T11:00:00Z" }, now)).toBe("stale")
    expect(backupState({ ok: true, at: "2026-10-28T11:00:00Z" }, now)).toBe("ok")
  })
  it("colours by UX.md: red only for a failure", () => {
    expect(STATE_COLOR.failed).toBe("--sev-critical")
    expect(STATE_COLOR.stale).toBe("--warning")
    expect(STATE_COLOR.ok).toBe("--success")
    expect(STATE_COLOR.none).toBe("--muted-foreground")
  })
})

describe("retention and restore", () => {
  it("counts what a smaller retention deletes", () => {
    expect(removedBy(3, 7)).toBe(4)
    expect(removedBy(7, 3)).toBe(0)
    expect(removedBy(0, 2)).toBe(1) // the server always keeps one
  })
  it("names the file in the restore commands, app stopped first", () => {
    const cmd = restoreCommand("cobe-news-20261029-120000.tar", "/data/backups/")
    expect(cmd.split("\n")).toEqual([
      "docker compose stop app",
      "docker compose run --rm --no-deps app python -m app.cli restore /data/backups/cobe-news-20261029-120000.tar",
      "docker compose start app",
    ])
  })
  it("hands an encrypted backup its passphrase by name, read without echo", () => {
    const lines = restoreCommand("cobe-news-20261029-120000.tar.enc").split("\n")
    expect(lines[0]).toBe("read -rs BACKUP_PASSPHRASE && export BACKUP_PASSPHRASE")
    expect(lines[2]).toBe("docker compose run --rm --no-deps -e BACKUP_PASSPHRASE app python -m app.cli restore /data/backups/cobe-news-20261029-120000.tar.enc")
  })
  it("has a text in both languages for every error kind of a backup", () => {
    for (const code of ["busy", "no_pg_dump", "timeout", "dump", "passphrase", "failed"]) {
      const key = backupErrorKey({ ok: false, at: "", code }) as keyof typeof de
      expect(de[key], key).toBeTruthy()
      expect(en[key as keyof typeof en], key).toBeTruthy()
    }
    expect(backupErrorKey({ ok: false, at: "" })).toBe("backup.err.failed")
  })
})

describe("i18n", () => {
  it("has every backup text in German and English", () => {
    const keys = (m: Record<string, string>) => Object.keys(m).filter((k) => k.startsWith("backup.") || k.includes("backup"))
    expect(keys(de).sort()).toEqual(keys(en).sort())
    expect(keys(de).length).toBeGreaterThan(40)
  })
})
