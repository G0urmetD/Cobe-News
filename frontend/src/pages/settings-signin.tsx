import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { useQueryClient } from "@tanstack/react-query"
import { CheckCircle2, Copy, Loader2, Plus, Search, Trash2, TriangleAlert, Users, XCircle } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Pill } from "@/components/cobe/badges"
import { EmptyState } from "@/components/cobe/common"
import { Explained } from "@/components/cobe/explained"
import { EnableCard, Field, LockedFields, ToggleRow } from "@/components/cobe/form"
import { copyWithToast } from "@/lib/clipboard"
import { api, ApiError, type Role } from "@/lib/api"
import {
  AUTH_CONTEXT,
  type DirectoryGroup,
  type EntraMfaMode,
  type EntraSettings,
  type LdapSettings,
  type MappingImpact,
  type MfaSettings,
  type SessionSettings,
  type SourceImpact,
  useEntra,
  useLdap,
  useMappings,
  useMfaSettings,
  useSessionSettings,
} from "@/lib/admin-api"
import { errorText } from "@/lib/errors"
import { withReauth } from "@/lib/reauth"
import { type DirectoryKind, type DirectoryTestResult as TestResult, directoryTestError, directoryTestToast } from "@/lib/directory-test"
import { type PasskeySettings, usePasskeySettings } from "@/lib/security-api"
import { NumberField, SaveBar, SheetActions, SheetBody, SheetLoading } from "@/pages/settings-shared"

function TestOutcome({ r, kind }: { r: TestResult | null; kind: DirectoryKind }) {
  const { t } = useTranslation()
  if (!r) return null
  if (!r.ok)
    return (
      <p className="flex items-center gap-1.5 rounded-lg border border-destructive/40 bg-destructive/10 p-2.5 text-xs">
        <XCircle className="size-4 shrink-0 text-destructive" /> {directoryTestError(t, r.error)}
      </p>
    )
  return (
    <div className="space-y-1.5">
      <p className="flex items-center gap-1.5 rounded-lg border border-success/40 bg-success/10 p-2.5 text-xs">
        <CheckCircle2 className="size-4 shrink-0 text-success" /> {t(`signin.${kind}.testOk`)}
      </p>
      {kind === "entra" && r.groups === "forbidden" && (
        <p className="flex items-center gap-1.5 rounded-lg border border-warning/40 bg-warning/10 p-2.5 text-xs">
          <TriangleAlert className="size-4 shrink-0 text-warning" /> {t("signin.entra.groupsForbidden")}
        </p>
      )}
    </div>
  )
}

/**
 * "Verbindung testen": the result as a toast (success, warning or the reason it failed) and in the box under the form
 * with the details. A request that fails as such (no answer, refused) is its toast alone – no box.
 */
function useConnectionTest(kind: DirectoryKind, setBusy: (b: "test" | null) => void, setResult: (r: TestResult | null) => void) {
  const { t } = useTranslation()
  return async (body: unknown) => {
    setBusy("test")
    setResult(null) // the box shows this run, not the one before
    try {
      const r = await api.post<TestResult>(`/api/admin/auth/${kind}/test`, body)
      setResult(r)
      const { level, text } = directoryTestToast(t, kind, r)
      toast[level](text)
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(null)
    }
  }
}

/**
 * Asks before taking access away (a role mapping removed, AD/LDAP or Entra ID switched off): what it does, how many
 * accounts it concerns (`impact`, loaded from the server; null while loading, "failed" when it could not be), and the
 * toggle "sign out those concerned at once" – on by default. `blocked`: the admin would lock itself out – explained,
 * no way to confirm (the server refuses it as well).
 */
function EndSessionsDialog({
  title,
  text,
  endHint,
  impact,
  blocked,
  confirm,
  onConfirm,
  onClose,
}: {
  title: string
  text: string
  endHint: string
  impact: string | null | "failed"
  blocked?: string
  confirm: string
  onConfirm: (endSessions: boolean) => void
  onClose: () => void
}) {
  const { t } = useTranslation()
  const [end, setEnd] = useState(true)
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription className="[overflow-wrap:anywhere]">{text}</DialogDescription>
        </DialogHeader>
        {blocked ? (
          <p className="flex gap-1.5 rounded-lg border border-warning/40 bg-warning/10 p-2.5 text-xs">
            <TriangleAlert className="size-4 shrink-0 text-warning" /> {blocked}
          </p>
        ) : (
          <>
            <ToggleRow label={t("signin.endSessions")} description={endHint} checked={end} onCheckedChange={setEnd} className="rounded-lg border px-3" />
            <p className="flex items-center gap-1.5 text-xs text-muted-foreground" aria-live="polite">
              {impact === null && <Loader2 className="size-3.5 animate-spin" />}
              {impact === null ? t("signin.impactLoading") : impact === "failed" ? t("signin.impactFailed") : impact}
            </p>
          </>
        )}
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          {!blocked && (
            <Button variant="destructive" disabled={impact === null} onClick={() => onConfirm(end)}>
              {confirm}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Loads what an action would take away (GET `url`) while the dialog is open: null while loading. */
function useImpact<T>(url: string | null): T | null | "failed" {
  const [r, setR] = useState<{ url: string; value: T | "failed" } | null>(null)
  useEffect(() => {
    if (!url) return
    let alive = true
    api.get<T>(url).then(
      (value) => alive && setR({ url, value }),
      () => alive && setR({ url, value: "failed" }),
    )
    return () => {
      alive = false
    }
  }, [url])
  return r && r.url === url ? r.value : null
}

/** "AD/LDAP or Entra ID off": the question before saving – sessions of its accounts end at once (toggle, on). */
function SwitchOffDialog({ kind, onConfirm, onClose }: { kind: DirectoryKind; onConfirm: (endSessions: boolean) => void; onClose: () => void }) {
  const { t } = useTranslation()
  const source = kind === "ldap" ? "Active Directory" : "Entra ID"
  const impact = useImpact<SourceImpact>(`/api/admin/auth/${kind}/impact`)
  const known = impact !== null && impact !== "failed"
  return (
    <EndSessionsDialog
      title={t("signin.off.title", { source })}
      text={t("signin.off.text", { source })}
      endHint={t("signin.off.endHint", { source })}
      impact={!known ? impact : impact.accounts === 0 ? t("signin.off.impactNone", { source }) : t("signin.off.impact", { count: impact.accounts, source })}
      blocked={known && impact.self ? t("signin.off.selfBlocked", { source }) : undefined}
      confirm={t("signin.off.confirm")}
      onConfirm={onConfirm}
      onClose={onClose}
    />
  )
}

// ---------------------------------------------------------------- Active Directory / LDAP

export function LdapPane() {
  const q = useLdap()
  if (!q.data) return <SheetLoading error={q.error} onRetry={q.refetch} />
  return <LdapForm key={JSON.stringify(q.data)} initial={q.data} />
}

function LdapForm({ initial }: { initial: LdapSettings }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { bind_password_set, usable: _usable, ...rest } = initial
  const [v, setV] = useState({ ...rest, bind_password: "" })
  const [servers, setServers] = useState(rest.servers.join("\n"))
  const [busy, setBusy] = useState<"save" | "test" | null>(null)
  const [result, setResult] = useState<TestResult | null>(null)
  const list = servers
    .split(/[\s,;]+/)
    .map((x) => x.trim())
    .filter(Boolean)
  const body = { ...v, servers: list }
  const dirty = JSON.stringify({ ...body, bind_password: "" }) !== JSON.stringify({ ...rest, bind_password: "" }) || !!v.bind_password
  const plainBlocked = v.encryption === "none" && !v.allow_plain
  const valid = list.length <= 4 && !plainBlocked && v.user_filter.includes("{username}") && v.timeout >= 2 && v.timeout <= 60
  const set = (patch: Partial<typeof v>) => {
    setV({ ...v, ...patch })
    setResult(null)
  }
  const [asking, setAsking] = useState(false)
  const save = async (end_sessions?: boolean) => {
    setBusy("save")
    try {
      await withReauth(() => api.put("/api/admin/auth/ldap", end_sessions === undefined ? body : { ...body, end_sessions }))
      setV((x) => ({ ...x, bind_password: "" })) // stored (encrypted) – the field empties, the form is clean
      toast.success(t("common.saved"))
      void qc.invalidateQueries({ queryKey: ["admin", "ldap"] })
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(null)
    }
  }
  const runTest = useConnectionTest("ldap", setBusy, setResult)
  const test = () => runTest(body)
  return (
    <>
      <SheetBody>
        <EnableCard label={t("signin.ldap.enabled")} description={t("signin.ldap.enabledHint")} checked={v.enabled} onCheckedChange={(x) => set({ enabled: x })} />
        <LockedFields locked={!v.enabled} className="space-y-4">
          <Field label={t("signin.ldap.servers")} hint={t("signin.ldap.serversHint")}>
            <Textarea
              value={servers}
              onChange={(e) => (setServers(e.target.value), setResult(null))}
              placeholder={"dc01.corp.example\ndc02.corp.example"}
              className="min-h-12 font-mono text-xs"
            />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={<Explained label={t("signin.ldap.encryption")} text={t("signin.ldap.encryptionHint")} />}>
              <Select value={v.encryption} onValueChange={(x) => set({ encryption: x as LdapSettings["encryption"] })}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent position="popper">
                  <SelectItem value="ldaps">LDAPS (636)</SelectItem>
                  <SelectItem value="starttls">StartTLS (389)</SelectItem>
                  <SelectItem value="none">{t("signin.ldap.plain")}</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <NumberField label={t("signin.ldap.timeout")} value={v.timeout} unit={t("signin.seconds")} min={2} max={60} onChange={(x) => set({ timeout: x })} />
          </div>
          {v.encryption === "none" ? (
            <ToggleRow
              label={t("signin.ldap.allowPlain")}
              description={<span className="text-warning">{t("signin.ldap.allowPlainHint")}</span>}
              checked={v.allow_plain}
              onCheckedChange={(x) => set({ allow_plain: x })}
              className="rounded-lg border border-warning/40 bg-warning/5 px-3"
            />
          ) : (
            <ToggleRow
              label={t("signin.ldap.verify")}
              description={t("signin.ldap.verifyHint")}
              checked={v.verify_cert}
              onCheckedChange={(x) => set({ verify_cert: x })}
              className="py-0"
            >
              <Field label={t("signin.ldap.ca")} hint={t("signin.ldap.caHint")}>
                <Textarea
                  value={v.ca_cert}
                  onChange={(e) => set({ ca_cert: e.target.value })}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  className="bg-background font-mono text-[11px]"
                />
              </Field>
            </ToggleRow>
          )}
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={<Explained label={t("signin.ldap.baseDn")} text={t("signin.ldap.baseDnHint")} />}>
              <Input value={v.base_dn} onChange={(e) => set({ base_dn: e.target.value })} placeholder="DC=corp,DC=example" className="font-mono text-xs" />
            </Field>
            <Field label={<Explained label={t("signin.ldap.bindDn")} text={t("signin.ldap.bindDnHint")} />}>
              <Input
                value={v.bind_dn}
                onChange={(e) => set({ bind_dn: e.target.value })}
                placeholder="CN=svc-cobe-news,OU=Service,DC=corp,DC=example"
                className="font-mono text-xs"
              />
            </Field>
          </div>
          <Field label={t("signin.ldap.bindPassword")} hint={bind_password_set ? t("common.secretKept") : t("signin.ldap.bindPasswordHint")}>
            <Input
              type="password"
              autoComplete="new-password"
              value={v.bind_password}
              onChange={(e) => set({ bind_password: e.target.value })}
              placeholder={bind_password_set ? "••••••••" : ""}
            />
          </Field>
          <Field label={<Explained label={t("signin.ldap.filter")} text={t("signin.ldap.filterHint")} />}>
            <Textarea
              value={v.user_filter}
              onChange={(e) => set({ user_filter: e.target.value })}
              className="min-h-12 font-mono text-[11px]"
              aria-invalid={!v.user_filter.includes("{username}")}
            />
          </Field>
          <ToggleRow
            label={t("signin.ldap.nested")}
            description={t("signin.ldap.nestedHint")}
            checked={v.nested_groups}
            onCheckedChange={(x) => set({ nested_groups: x })}
            className="py-0"
          />
        </LockedFields>
        <TestOutcome r={result} kind="ldap" />
        <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("signin.ldap.about")}</p>
      </SheetBody>
      <SheetActions>
        <Button variant="outline" disabled={busy !== null || list.length === 0 || plainBlocked} onClick={() => void test()}>
          {busy === "test" && <Loader2 className="animate-spin" />} {t("signin.test")}
        </Button>
        {/* switched off: asked first – the sessions of its accounts end at once (toggle) */}
        <SaveBar busy={busy === "save"} dirty={dirty} disabled={!valid || busy === "test"} onSave={() => (initial.enabled && !v.enabled ? setAsking(true) : void save())} />
      </SheetActions>
      {asking && <SwitchOffDialog kind="ldap" onClose={() => setAsking(false)} onConfirm={(end) => (setAsking(false), void save(end))} />}
    </>
  )
}

// ---------------------------------------------------------------- Entra ID

export function EntraPane() {
  const q = useEntra()
  if (!q.data) return <SheetLoading error={q.error} onRetry={q.refetch} />
  return <EntraForm key={JSON.stringify(q.data)} initial={q.data} />
}

const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/

function EntraForm({ initial }: { initial: EntraSettings }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [v, setV] = useState({
    enabled: initial.enabled,
    tenant_id: initial.tenant_id,
    client_id: initial.client_id,
    client_secret: "",
    mfa_mode: initial.mfa_mode ?? "entra",
    auth_context: (initial.auth_context ?? "").toUpperCase(),
    rev: initial.rev,
  })
  const [busy, setBusy] = useState<"save" | "test" | null>(null)
  const [result, setResult] = useState<TestResult | null>(null)
  const dirty =
    v.enabled !== initial.enabled ||
    v.tenant_id !== initial.tenant_id ||
    v.client_id !== initial.client_id ||
    !!v.client_secret ||
    v.mfa_mode !== (initial.mfa_mode ?? "entra") ||
    v.auth_context.toLowerCase() !== (initial.auth_context ?? "")
  const contextOk = v.auth_context === "" ? v.mfa_mode !== "context" : AUTH_CONTEXT.test(v.auth_context)
  const idsOk = (!v.tenant_id || GUID.test(v.tenant_id)) && (!v.client_id || GUID.test(v.client_id)) && contextOk
  const set = (patch: Partial<typeof v>) => {
    setV({ ...v, ...patch })
    setResult(null)
  }
  const [asking, setAsking] = useState(false)
  const save = async (end_sessions?: boolean) => {
    setBusy("save")
    try {
      await withReauth(() => api.put("/api/admin/auth/entra", end_sessions === undefined ? v : { ...v, end_sessions }))
      setV((x) => ({ ...x, client_secret: "" })) // stored (encrypted) – the field empties, the form is clean
      toast.success(t("common.saved"))
      void qc.invalidateQueries({ queryKey: ["admin", "entra"] })
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(null)
    }
  }
  const runTest = useConnectionTest("entra", setBusy, setResult)
  const test = () => runTest(v)
  return (
    <>
      <SheetBody>
        <EnableCard label={t("signin.entra.enabled")} description={t("signin.entra.enabledHint")} checked={v.enabled} onCheckedChange={(x) => set({ enabled: x })} />
        <LockedFields locked={!v.enabled} className="space-y-4">
          <Field label={<Explained label={t("signin.entra.redirect")} text={t("signin.entra.redirectHint")} />}>
            <div className="flex items-center gap-2 rounded-lg bg-muted px-3 py-2">
              <code className="min-w-0 flex-1 font-mono text-xs break-all">{initial.redirect_uri}</code>
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                aria-label={t("common.copy")}
                onClick={() => {
                  void copyWithToast(initial.redirect_uri)
                }}
              >
                <Copy />
              </Button>
            </div>
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={<Explained label={t("signin.entra.tenant")} text={t("signin.entra.tenantHint")} />}>
              <Input
                value={v.tenant_id}
                onChange={(e) => set({ tenant_id: e.target.value.trim() })}
                placeholder="00000000-0000-0000-0000-000000000000"
                className="font-mono text-xs"
                aria-invalid={!!v.tenant_id && !GUID.test(v.tenant_id)}
              />
            </Field>
            <Field label={<Explained label={t("signin.entra.client")} text={t("signin.entra.clientHint")} />}>
              <Input
                value={v.client_id}
                onChange={(e) => set({ client_id: e.target.value.trim() })}
                placeholder="00000000-0000-0000-0000-000000000000"
                className="font-mono text-xs"
                aria-invalid={!!v.client_id && !GUID.test(v.client_id)}
              />
            </Field>
          </div>
          <Field label={<Explained label={t("signin.entra.secret")} text={t("signin.entra.secretHint")} />} hint={initial.client_secret_set ? t("common.secretKept") : undefined}>
            <Input
              type="password"
              autoComplete="new-password"
              value={v.client_secret}
              onChange={(e) => set({ client_secret: e.target.value })}
              placeholder={initial.client_secret_set ? "••••••••" : ""}
            />
          </Field>
          <EntraMfaFields mode={v.mfa_mode} context={v.auth_context} onChange={(p) => set(p)} />
        </LockedFields>
        <TestOutcome r={result} kind="entra" />
        <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("signin.entra.about")}</p>
      </SheetBody>
      <SheetActions>
        <Button
          variant="outline"
          disabled={busy !== null || !v.tenant_id || !v.client_id || !idsOk || (!v.client_secret && !initial.client_secret_set)}
          onClick={() => void test()}
        >
          {busy === "test" && <Loader2 className="animate-spin" />} {t("signin.test")}
        </Button>
        <SaveBar busy={busy === "save"} dirty={dirty} disabled={!idsOk || busy === "test"} onSave={() => (initial.enabled && !v.enabled ? setAsking(true) : void save())} />
      </SheetActions>
      {asking && <SwitchOffDialog kind="entra" onClose={() => setAsking(false)} onConfirm={(end) => (setAsking(false), void save(end))} />}
    </>
  )
}

/**
 * "MFA-Nachweis": what proves the second factor of an Entra sign-in – Conditional Access trusted (readers as before,
 * admins only with a proof in the token), an authentication context the token must carry, or a proof / the own TOTP.
 * While no context is configured: a hint – without one, Cobe News cannot see whether Microsoft asked for MFA.
 */
function EntraMfaFields({ mode, context, onChange }: { mode: EntraMfaMode; context: string; onChange: (p: { mfa_mode?: EntraMfaMode; auth_context?: string }) => void }) {
  const { t } = useTranslation()
  const contextBad = context !== "" && !AUTH_CONTEXT.test(context)
  return (
    <div className="space-y-3 rounded-lg border p-3">
      <Field label={<Explained label={t("signin.entra.mfa")} text={t("signin.entra.mfaHint")} />} hint={t(`signin.entra.mfa.${mode}Hint`)}>
        <Select value={mode} onValueChange={(x) => onChange({ mfa_mode: x as EntraMfaMode })}>
          <SelectTrigger className="w-full sm:max-w-sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent position="popper">
            <SelectItem value="entra">{t("signin.entra.mfa.entra")}</SelectItem>
            <SelectItem value="context">{t("signin.entra.mfa.context")}</SelectItem>
            <SelectItem value="require">{t("signin.entra.mfa.require")}</SelectItem>
          </SelectContent>
        </Select>
      </Field>
      {mode === "context" && (
        <Field label={<Explained label={t("signin.entra.context")} text={t("signin.entra.contextHint")} />} hint={contextBad ? t("signin.entra.contextBad") : undefined}>
          <Input
            value={context}
            onChange={(e) => onChange({ auth_context: e.target.value.trim().toUpperCase() })}
            placeholder="C1"
            maxLength={3}
            className="w-28 font-mono text-xs"
            aria-invalid={contextBad || context === ""}
          />
        </Field>
      )}
      {(mode !== "context" || !AUTH_CONTEXT.test(context)) && (
        <p className="flex items-start gap-1.5 rounded-lg border border-warning/40 bg-warning/10 p-2.5 text-xs">
          <TriangleAlert className="size-4 shrink-0 text-warning" /> {t("signin.entra.noContext")}
        </p>
      )}
    </div>
  )
}

// ---------------------------------------------------------------- the second factor for everybody

/** Einstellungen → Anmeldung → Zweiter Faktor: "Zweiter Faktor für alle Pflicht" (off by default). */
export function SecondFactorPane() {
  const q = useMfaSettings()
  if (!q.data) return <SheetLoading error={q.error} onRetry={q.refetch} />
  return <SecondFactorForm key={JSON.stringify(q.data)} initial={q.data} />
}

function SecondFactorForm({ initial }: { initial: MfaSettings }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [on, setOn] = useState(initial.required_all)
  const [busy, setBusy] = useState(false)
  const save = async () => {
    setBusy(true)
    try {
      await withReauth(() => api.put("/api/admin/auth/mfa", { required_all: on, rev: initial.rev }))
      toast.success(t("common.saved"))
      void qc.invalidateQueries({ queryKey: ["admin", "mfa"] })
    } catch (e) {
      toast.error(errorText(t, e))
      if (e instanceof ApiError && e.code === "stale") void qc.invalidateQueries({ queryKey: ["admin", "mfa"] })
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <SheetBody>
        <ToggleRow
          label={t("signin.mfa.requiredAll")}
          description={<Explained label={t("signin.mfa.requiredAllHint")} text={t("signin.mfa.tip")} />}
          checked={on}
          onCheckedChange={setOn}
          className="py-0"
        />
        <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("signin.mfa.about")}</p>
      </SheetBody>
      <SheetActions>
        <span />
        <SaveBar busy={busy} dirty={on !== initial.required_all} onSave={() => void save()} />
      </SheetActions>
    </>
  )
}

// ---------------------------------------------------------------- group → role

export function MappingsPane() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const q = useMappings()
  const ldap = useLdap().data
  const entra = useEntra().data
  const [source, setSource] = useState<"ldap" | "entra">("ldap")
  const [role, setRole] = useState<Role>("reader")
  const [query, setQuery] = useState("")
  const [groups, setGroups] = useState<DirectoryGroup[] | null>(null)
  const [searching, setSearching] = useState(false)
  const [searchError, setSearchError] = useState<string | null>(null)
  const [picked, setPicked] = useState<DirectoryGroup | null>(null)
  const usable = source === "ldap" ? !!ldap?.usable : !!entra?.usable

  // live search, debounced – in the directory itself, never a list kept here
  useEffect(() => {
    setGroups(null)
    setSearchError(null)
    if (!usable) return
    let alive = true
    const id = setTimeout(async () => {
      setSearching(true)
      try {
        const r = await api.get<DirectoryGroup[]>(`/api/admin/auth/${source}/groups?q=${encodeURIComponent(query)}`)
        if (alive) setGroups(r)
      } catch (e) {
        if (alive) setSearchError(errorText(t, e))
      } finally {
        if (alive) setSearching(false)
      }
    }, 350)
    return () => {
      alive = false
      clearTimeout(id)
    }
  }, [query, source, usable, t])

  const add = async () => {
    if (!picked) return
    try {
      await withReauth(() => api.post("/api/admin/auth/mappings", { source, group_id: picked.id, group_name: picked.name, role }))
      setPicked(null)
      void qc.invalidateQueries({ queryKey: ["admin", "mappings"] })
      toast.success(t("signin.map.added"))
    } catch (e) {
      toast.error(e instanceof ApiError ? errorText(t, e) : t("errors.generic"))
    }
  }
  const [removing, setRemoving] = useState<{ id: string; name: string } | null>(null)
  // with "sign out at once" the server re-checks the accounts the group concerned right away (and says how many)
  const remove = async (id: string, endSessions: boolean) => {
    setRemoving(null)
    try {
      const r = await withReauth(() => api.del<{ affected: number }>(`/api/admin/auth/mappings/${id}?end_sessions=${endSessions}`))
      void qc.invalidateQueries({ queryKey: ["admin", "mappings"] })
      void qc.invalidateQueries({ queryKey: ["admin", "users"] })
      toast.success(r.affected > 0 ? t("signin.map.removedSignedOut", { count: r.affected }) : t("signin.map.removed"))
    } catch (e) {
      toast.error(errorText(t, e))
    }
  }
  if (!q.data) return <SheetLoading error={q.error} onRetry={q.refetch} />
  return (
    <>
      <SheetBody>
        {q.data.length === 0 ? (
          <EmptyState icon={Users} title={t("signin.map.emptyTitle")} text={t("signin.map.emptyText")} />
        ) : (
          <ul className="divide-y rounded-lg border">
            {q.data.map((m) => (
              <li key={m.id} className="flex items-center gap-3 px-3 py-2.5">
                <Pill color="--muted-foreground">{m.source === "ldap" ? "AD" : "Entra"}</Pill>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{m.group_name || m.group_id}</p>
                  <p className="truncate font-mono text-[11px] text-muted-foreground" title={m.group_id}>
                    {m.group_id}
                  </p>
                </div>
                <Pill color={m.role === "admin" ? "--sev-high" : "--primary"}>{t(`role.${m.role}`)}</Pill>
                <Button variant="ghost" size="icon-sm" aria-label={t("common.remove")} onClick={() => setRemoving({ id: m.id, name: m.group_name || m.group_id })}>
                  <Trash2 />
                </Button>
              </li>
            ))}
          </ul>
        )}
        <div className="space-y-3 rounded-lg border border-dashed p-3">
          <p className="text-sm font-medium">{t("signin.map.addTitle")}</p>
          <div className="grid gap-3 sm:grid-cols-[1fr_2fr]">
            <Field label={t("signin.map.source")}>
              <Select value={source} onValueChange={(x) => (setSource(x as "ldap" | "entra"), setPicked(null))}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent position="popper">
                  <SelectItem value="ldap">Active Directory</SelectItem>
                  <SelectItem value="entra">Entra ID</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field label={t("signin.map.search")}>
              <div className="relative">
                <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("signin.map.searchPlaceholder")} className="pl-8" disabled={!usable} />
              </div>
            </Field>
          </div>
          {!usable ? (
            <p className="text-xs text-muted-foreground">{t(`signin.map.notConfigured.${source}`)}</p>
          ) : searchError ? (
            <p className="text-xs text-destructive">{searchError}</p>
          ) : searching && !groups ? (
            <Loader2 className="size-4 animate-spin text-muted-foreground" />
          ) : groups && groups.length === 0 ? (
            <p className="text-xs text-muted-foreground">{t("common.noResults")}</p>
          ) : (
            groups && (
              <ul className="max-h-56 divide-y overflow-y-auto rounded-lg border" role="listbox" aria-label={t("signin.map.results")}>
                {groups.map((g) => (
                  <li key={g.id}>
                    <button
                      type="button"
                      role="option"
                      aria-selected={picked?.id === g.id}
                      onClick={() => setPicked(g)}
                      className={"w-full px-3 py-2 text-left hover:bg-muted/50 " + (picked?.id === g.id ? "bg-primary/5 ring-1 ring-primary ring-inset" : "")}
                    >
                      <span className="block text-sm font-medium">{g.name}</span>
                      <span className="block truncate text-[11px] text-muted-foreground">{g.path || g.description || g.id}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )
          )}
          <div className="flex flex-wrap items-end justify-end gap-2">
            <Field label={t("signin.map.role")}>
              <Select value={role} onValueChange={(x) => setRole(x as Role)}>
                <SelectTrigger className="w-36">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent position="popper">
                  <SelectItem value="reader">{t("role.reader")}</SelectItem>
                  <SelectItem value="admin">{t("role.admin")}</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Button disabled={!picked} onClick={() => void add()}>
              <Plus /> {picked ? t("signin.map.addPicked", { name: picked.name }) : t("signin.map.add")}
            </Button>
          </div>
        </div>
      </SheetBody>
      {removing && <RemoveMappingDialog key={removing.id} {...removing} onConfirm={(end) => void remove(removing.id, end)} onClose={() => setRemoving(null)} />}
    </>
  )
}

function RemoveMappingDialog({ id, name, onConfirm, onClose }: { id: string; name: string; onConfirm: (endSessions: boolean) => void; onClose: () => void }) {
  const { t } = useTranslation()
  const impact = useImpact<MappingImpact>(`/api/admin/auth/mappings/${id}/impact`)
  const known = impact !== null && impact !== "failed"
  const parts = known
    ? [
        impact.lost > 0 && t("signin.map.impactLost", { count: impact.lost }),
        impact.demoted > 0 && t("signin.map.impactDemoted", { count: impact.demoted }),
        impact.unknown > 0 && t("signin.map.impactUnknown", { count: impact.unknown }),
      ].filter(Boolean)
    : []
  return (
    <EndSessionsDialog
      title={t("signin.map.removeTitle")}
      text={t("signin.map.removeText", { name })}
      endHint={t("signin.map.endHint")}
      impact={!known ? impact : parts.length ? parts.join(" ") : t("signin.map.impactNone")}
      blocked={known && impact.self ? t("signin.map.selfBlocked") : undefined}
      confirm={t("common.remove")}
      onConfirm={onConfirm}
      onClose={onClose}
    />
  )
}

// ---------------------------------------------------------------- sessions

export function SessionsPane() {
  const q = useSessionSettings()
  if (!q.data) return <SheetLoading error={q.error} onRetry={q.refetch} />
  return <SessionsForm key={JSON.stringify(q.data)} initial={q.data} />
}

function SessionsForm({ initial }: { initial: SessionSettings }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [v, setV] = useState(initial)
  const [busy, setBusy] = useState(false)
  const valid = v.idle_min >= 5 && v.idle_min <= 480 && v.absolute_h >= 1 && v.absolute_h <= 72
  const save = async () => {
    setBusy(true)
    try {
      await withReauth(() => api.put("/api/admin/auth/sessions", v))
      toast.success(t("common.saved"))
      void qc.invalidateQueries({ queryKey: ["admin", "sessions"] })
    } catch (e) {
      toast.error(errorText(t, e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <SheetBody>
        <NumberField
          label={t("signin.sessions.idle")}
          hint={t("signin.sessions.idleHint")}
          value={v.idle_min}
          unit={t("settings.news.minutes")}
          min={5}
          max={480}
          onChange={(x) => setV({ ...v, idle_min: x })}
        />
        <NumberField
          label={t("signin.sessions.absolute")}
          hint={t("signin.sessions.absoluteHint")}
          value={v.absolute_h}
          unit={t("signin.hours")}
          min={1}
          max={72}
          onChange={(x) => setV({ ...v, absolute_h: x })}
        />
        <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("signin.sessions.about")}</p>
      </SheetBody>
      <SheetActions>
        <span />
        <SaveBar busy={busy} dirty={JSON.stringify(v) !== JSON.stringify(initial)} disabled={!valid} onSave={() => void save()} />
      </SheetActions>
    </>
  )
}

/** Einstellungen → Anmeldung → Passkeys: the switch (on by default) and whether BASE_URL allows them at all. */
export function PasskeysPane() {
  const q = usePasskeySettings()
  if (!q.data) return <SheetLoading error={q.error} onRetry={q.refetch} />
  return <PasskeysForm key={JSON.stringify(q.data)} initial={q.data} />
}

function PasskeysForm({ initial }: { initial: PasskeySettings }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [enabled, setEnabled] = useState(initial.enabled)
  const [busy, setBusy] = useState(false)
  const save = async () => {
    setBusy(true)
    try {
      await withReauth(() => api.put("/api/admin/auth/passkeys", { enabled, rev: initial.rev }))
      toast.success(t("common.saved"))
      void qc.invalidateQueries({ queryKey: ["admin", "passkeys"] })
    } catch (e) {
      toast.error(errorText(t, e))
      if (e instanceof ApiError && e.code === "stale") void qc.invalidateQueries({ queryKey: ["admin", "passkeys"] })
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <SheetBody>
        <ToggleRow
          label={t("signin.passkeys.enabled")}
          description={<Explained label={t("signin.passkeys.enabledHint")} text={t("glossary.webauthnText")} />}
          checked={enabled}
          onCheckedChange={setEnabled}
          className="py-0"
        />
        {initial.available ? (
          <p className="rounded-lg bg-muted/60 p-3 text-xs text-muted-foreground">{t("signin.passkeys.boundTo", { rp: initial.rp_id, origin: initial.origin })}</p>
        ) : (
          <p className="flex items-start gap-1.5 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">
            <TriangleAlert className="size-4 shrink-0 text-warning" />
            {t(`passkey.unavailable.${initial.reason ?? "bad_host"}`, { defaultValue: t("errors.passkey_unavailable") })}
          </p>
        )}
      </SheetBody>
      <SheetActions>
        <span />
        <SaveBar busy={busy} dirty={enabled !== initial.enabled} onSave={() => void save()} />
      </SheetActions>
    </>
  )
}
