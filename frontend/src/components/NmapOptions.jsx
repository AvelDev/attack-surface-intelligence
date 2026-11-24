import { useEffect, useMemo, useState } from "react";
import { ChevronDown, Copy, X } from "lucide-react";
import { api } from "../api.js";
import { useI18n } from "../i18n.jsx";
import { Check, Command, Field } from "./ui.jsx";

export const FAST = "fast"; // samo naabu, bez nmapa
const TCP = ["syn", "connect", "ack", "window", "maimon", "null", "fin", "xmas"];
const SCTP = ["sctp_init", "sctp_cookie"];
const FLAGS = ["SYN", "ACK", "FIN", "RST", "PSH", "URG"];
const PING_WITH_PORTS = ["syn", "ack", "udp", "sctp"];
const LAST = "asi.nmap.profile";

// Pola należące do zakładki: z nich liczymy, ile opcji operator zmienił względem profilu.
const GROUPS = {
  hosts: ["mode", "discovery", "ping", "ping_ports", "disable_arp_ping", "traceroute", "dns"],
  ports: ["prescan", "port_mode", "top_ports", "ports", "exclude_ports", "sequential"],
  tech: ["techniques", "scanflags"],
  svc: ["version", "version_intensity", "os", "os_limit", "os_guess"],
  nse: ["script_categories", "scripts", "script_args", "script_timeout_s"],
  speed: ["timing", "min_rate", "max_retries", "host_timeout_s", "scan_delay_ms", "max_parallelism"],
  pkt: ["fragment", "mtu", "source_port", "data_length", "ttl", "badsum"],
};

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** Możliwości nmapa na serwerze: profile, techniki, kategorie NSE. null = jeszcze nie wiadomo. */
export function useNmapInfo() {
  const [info, setInfo] = useState(null);
  useEffect(() => {
    let live = true;
    api.nmap().then((d) => live && setInfo(d)).catch(() => live && setInfo({ installed: false, profiles: [] }));
    return () => { live = false; };
  }, []);
  return info;
}

export function lastProfile() {
  try { return localStorage.getItem(LAST) || "service"; } catch (e) { return "service"; }
}

export function rememberProfile(id) {
  try { localStorage.setItem(LAST, id); } catch (e) { /* prywatne okno */ }
}

/** Etykieta profilu zapisanego w opcjach skanu (null = skan bez nmapa). */
export function profileName(t, nmap) {
  return t(`nm.p.${nmap ? nmap.profile || "custom" : FAST}`);
}

/** Opcje zapisane w skanie (bez wartości domyślnych) -> komplet pól formularza. */
export const fillOptions = (info, stored) => (stored && info?.defaults ? { ...info.defaults, ...stored } : null);

export function ProfileSelect({ info, value, onChange, custom = true }) {
  const { t } = useI18n();
  const id = value ? value.profile : FAST;
  const pick = (next) => {
    rememberProfile(next);
    onChange(next === FAST ? null : info.profiles.find((p) => p.profile === next) || { ...info.defaults, profile: "custom" });
  };
  return (
    <Field label={t("nm.profile")} hint={t(!info ? "nm.checking" : !info.installed ? "nm.missing" : `nm.d.${id}`)} className="span-2">
      <select value={id} disabled={!info?.installed} onChange={(e) => pick(e.target.value)}>
        <option value={FAST}>{info ? t(`nm.p.${FAST}`) : "…"}</option>
        {(info?.profiles || []).map((p) => <option key={p.profile} value={p.profile}>{t(`nm.p.${p.profile}`)}</option>)}
        {custom && <option value="custom">{t("nm.p.custom")}</option>}
      </select>
    </Field>
  );
}

/** Profil, szczegółowe opcje w zakładkach i podgląd dokładnej komendy. */
export default function NmapOptions({ info, value, onChange, rate, intel }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(value?.profile === "custom");
  const [tab, setTab] = useState("hosts");
  const [base, setBase] = useState(null); // profil, od którego operator zaczął zmiany
  const profile = info?.profiles.find((p) => p.profile === (base || value?.profile)) || info?.defaults;

  const pickProfile = (next) => {
    setBase(next && next.profile !== "custom" ? next.profile : null);
    if (next?.profile === "custom") setOpen(true);
    onChange(next);
  };
  const set = (patch) => {
    const next = { ...value, ...patch };
    const start = info.profiles.find((p) => p.profile === (base || value.profile));
    if (start && !base) setBase(start.profile);
    // powrót do wartości profilu przywraca jego nazwę
    onChange({ ...next, profile: start && same({ ...next, profile: start.profile }, start) ? start.profile : "custom" });
  };
  const changed = (g) => (value && profile ? GROUPS[g].filter((k) => !same(value[k], profile[k])).length : 0);
  const Panel = PANELS[tab];

  return (
    <fieldset className="span-2 fs nm">
      <legend>nmap{info?.version ? ` ${info.version}` : ""}</legend>
      <ProfileSelect info={info} value={value} onChange={pickProfile} />
      {value && info?.installed && (
        <>
          {!info.raw && <p className="nm-note">{t("nm.noRaw")}</p>}
          <button type="button" className="btn btn-sm nm-toggle" aria-expanded={open} aria-controls="nm-panel" onClick={() => setOpen(!open)}>
            <ChevronDown size={13} aria-hidden="true" className={open ? "is-open" : ""} /> {t(open ? "nm.hide" : "nm.adjust")}
          </button>
          {open && (
            <div className="nm-adv" id="nm-panel">
              <div className="tabs nm-tabs" role="tablist" aria-label={t("nm.adjust")}>
                {Object.keys(GROUPS).map((g) => {
                  const n = changed(g);
                  return (
                    <button key={g} type="button" role="tab" id={`nm-tab-${g}`} aria-selected={tab === g} aria-controls={`nm-p-${g}`} onClick={() => setTab(g)}>
                      {t(`nm.g.${g}`)}
                      {n > 0 && <span className="mono nm-n" title={t("nm.changed", { n })}> {n}</span>}
                    </button>
                  );
                })}
              </div>
              <div className="nm-panel" role="tabpanel" id={`nm-p-${tab}`} aria-labelledby={`nm-tab-${tab}`}>
                <Panel v={value} set={set} info={info} t={t} intel={intel} />
              </div>
            </div>
          )}
          <Preview value={value} rate={rate} intel={intel} />
        </>
      )}
    </fieldset>
  );
}

// ---------- drobne kontrolki ----------
function Num({ label, hint, value, onChange, min, max, step = 1, placeholder, disabled }) {
  return (
    <Field label={label} hint={hint}>
      <input className="mono" type="number" inputMode="numeric" min={min} max={max} step={step} disabled={disabled} placeholder={placeholder}
             value={value ?? ""} onChange={(e) => onChange(e.target.value === "" ? null : Math.trunc(+e.target.value))} />
    </Field>
  );
}

function Text({ label, hint, value, onChange, placeholder, disabled, className }) {
  return (
    <Field label={label} hint={hint} className={className}>
      <input className="mono" value={value} disabled={disabled} placeholder={placeholder} spellCheck={false} autoComplete="off" onChange={(e) => onChange(e.target.value)} />
    </Field>
  );
}

function Select({ label, hint, value, onChange, options, disabled }) {
  return (
    <Field label={label} hint={hint}>
      <select value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)}>
        {options.map(([id, text, off]) => <option key={id} value={id} disabled={off}>{text}</option>)}
      </select>
    </Field>
  );
}

const Flag = ({ children }) => <code className="nm-flag">{children}</code>;
const toggle = (list, item, on) => (on ? [...list, item] : list.filter((x) => x !== item));

// ---------- zakładki ----------
function Hosts({ v, set, info, t }) {
  const custom = v.discovery === "custom";
  return (
    <div className="form-grid">
      <Select label={t("nm.mode")} value={v.mode} options={[["ports", t("nm.mode.ports")], ["hosts", t("nm.mode.hosts")]]}
              onChange={(mode) => set(mode === "hosts" ? { mode, prescan: false, discovery: v.discovery === "skip" ? "default" : v.discovery } : { mode })} />
      <Select label={t("nm.discovery")} value={v.discovery} onChange={(discovery) => set({ discovery, ping: discovery === "custom" && !v.ping.length ? ["syn"] : v.ping })}
              options={[["skip", t("nm.disc.skip"), v.mode === "hosts"], ["default", t("nm.disc.default")], ["custom", t("nm.disc.custom")]]} />
      {custom && (
        <div className="span-2 nm-checks" role="group" aria-label={t("nm.disc.custom")}>
          {Object.entries(info.pings).map(([id, flag]) => (
            <Check key={id} checked={v.ping.includes(id)} disabled={!info.raw && id !== "syn"} onChange={(on) => set({ ping: toggle(v.ping, id, on) })}>
              {t(`nm.ping.${id}`)} <Flag>{flag}</Flag>
            </Check>
          ))}
        </div>
      )}
      {custom && v.ping.some((p) => PING_WITH_PORTS.includes(p)) && (
        <Text label={t("nm.pingPorts")} value={v.ping_ports} placeholder="22,80,443" onChange={(ping_ports) => set({ ping_ports })} />
      )}
      <Select label={t("nm.dns")} value={v.dns} onChange={(dns) => set({ dns })}
              options={["never", "auto", "always"].map((x) => [x, t(`nm.dns.${x}`)])} />
      <div className="span-2 nm-checks">
        <Check checked={v.traceroute} disabled={!info.raw} onChange={(traceroute) => set({ traceroute })}>{t("nm.traceroute")} <Flag>--traceroute</Flag></Check>
        <Check checked={v.disable_arp_ping} onChange={(disable_arp_ping) => set({ disable_arp_ping })}>{t("nm.noArp")} <Flag>--disable-arp-ping</Flag></Check>
      </div>
    </div>
  );
}

function Ports({ v, set, info, t }) {
  if (v.mode === "hosts") return <p className="quiet nm-empty">{t("nm.hostsOnly")}</p>;
  const protocol = v.techniques.includes("protocol");
  return (
    <div className="form-grid">
      <Select label={t("nm.portMode")} value={v.port_mode} onChange={(port_mode) => set({ port_mode })}
              options={[["top", t("nm.pm.top"), protocol], ["default", t("nm.pm.default")], ["range", t("nm.pm.range")], ["all", t("nm.pm.all")]]} />
      {v.port_mode === "top" && <Num label={t("nm.topPorts")} value={v.top_ports} min={1} max={65535} onChange={(x) => set({ top_ports: x ?? 1 })} />}
      {v.port_mode === "range" && <Text label={t("nm.ports")} value={v.ports} placeholder="22,80,443,8000-9000" onChange={(ports) => set({ ports })} />}
      <Text label={t("nm.exclude")} value={v.exclude_ports} placeholder="9100,515" onChange={(exclude_ports) => set({ exclude_ports })} />
      <div className="span-2 nm-checks">
        <Check checked={v.prescan} disabled={!info.naabu || !v.techniques.every((x) => x === "syn" || x === "connect")} onChange={(prescan) => set({ prescan })}>
          {t("nm.prescan")}{!info.naabu && ` (${t("ns.unavailable")})`}
        </Check>
        <Check checked={v.sequential} onChange={(sequential) => set({ sequential })}>{t("nm.sequential")} <Flag>-r</Flag></Check>
      </div>
    </div>
  );
}

function Tech({ v, set, info, t }) {
  if (v.mode === "hosts") return <p className="quiet nm-empty">{t("nm.hostsOnly")}</p>;
  const tcp = v.techniques.find((x) => TCP.includes(x)) || "";
  const sctp = v.techniques.find((x) => SCTP.includes(x)) || "";
  const udp = v.techniques.includes("udp");
  const protocol = v.techniques.includes("protocol");
  const build = (next) => {
    const s = { tcp, sctp, udp, ...next };
    const techniques = [s.tcp, s.udp && "udp", s.sctp].filter(Boolean);
    if (!techniques.length) return;
    set({ techniques, prescan: v.prescan && techniques.every((x) => x === "syn" || x === "connect"), scanflags: !s.tcp || s.tcp === "connect" ? [] : v.scanflags });
  };
  const opt = (x) => [x, `${t(`nm.t.${x}`)} (${info.techniques[x]})`, !info.raw && x !== "connect" && x !== "syn"];
  return (
    <div className="form-grid">
      <Select label={t("nm.tcp")} hint={tcp ? t(`nm.th.${tcp}`) : null} value={tcp} disabled={protocol} onChange={(x) => build({ tcp: x })}
              options={[["", t("nm.none"), !udp && !sctp], ...TCP.map(opt)]} />
      <Select label="SCTP" value={sctp} disabled={protocol || !info.raw} onChange={(x) => build({ sctp: x })}
              options={[["", t("nm.none"), !udp && !tcp], ...SCTP.map(opt)]} />
      <div className="span-2 nm-checks">
        <Check checked={udp} disabled={protocol || !info.raw} onChange={(on) => build({ udp: on, tcp: !on && !tcp && !sctp ? "syn" : tcp })}>{t("nm.t.udp")} <Flag>-sU</Flag></Check>
        <Check checked={protocol} disabled={!info.raw}
               onChange={(on) => set(on ? { techniques: ["protocol"], prescan: false, scanflags: [], version: false, port_mode: v.port_mode === "top" ? "default" : v.port_mode } : { techniques: ["syn"] })}>
          {t("nm.t.protocol")} <Flag>-sO</Flag>
        </Check>
      </div>
      {tcp && tcp !== "connect" && (
        <div className="span-2 nm-checks nm-inline" role="group" aria-label={t("nm.scanflags")}>
          <span className="nm-lab">{t("nm.scanflags")} <Flag>--scanflags</Flag></span>
          {FLAGS.map((f) => (
            <Check key={f} checked={v.scanflags.includes(f)} disabled={!info.raw} onChange={(on) => set({ scanflags: toggle(v.scanflags, f, on) })}><code>{f}</code></Check>
          ))}
        </div>
      )}
    </div>
  );
}

function Services({ v, set, info, t }) {
  if (v.mode === "hosts") return <p className="quiet nm-empty">{t("nm.hostsOnly")}</p>;
  return (
    <div className="form-grid">
      <div className="span-2 nm-checks">
        <Check checked={v.version} disabled={v.techniques.includes("protocol")} onChange={(version) => set({ version })}>{t("nm.version")} <Flag>-sV</Flag></Check>
      </div>
      <Select label={t("nm.intensity")} disabled={!v.version} value={v.version_intensity ?? ""} onChange={(x) => set({ version_intensity: x === "" ? null : +x })}
              options={[["", t("nm.int.auto")], ...Array.from({ length: 10 }, (_, i) => [i, t("nm.int", { n: i }) + (i === 0 ? t("nm.int.low") : i === 2 ? t("nm.int.light") : i === 9 ? t("nm.int.all") : "")])]} />
      <div className="span-2 nm-checks">
        <Check checked={v.os} disabled={!info.raw} onChange={(os) => set({ os })}>{t("nm.os")} <Flag>-O</Flag></Check>
        <Check checked={v.os_guess} disabled={!v.os} onChange={(os_guess) => set({ os_guess })}>{t("nm.osGuess")} <Flag>--osscan-guess</Flag></Check>
        <Check checked={v.os_limit} disabled={!v.os} onChange={(os_limit) => set({ os_limit })}>{t("nm.osLimit")} <Flag>--osscan-limit</Flag></Check>
      </div>
    </div>
  );
}

function Nse({ v, set, info, t, intel }) {
  const why = (c) => (c.gated && !c.allowed ? t("nm.gated") : c.external && !intel ? t("nm.needsIntel") : null);
  return (
    <div className="form-grid">
      <div className="span-2 nm-cats" role="group" aria-label={t("nm.categories")}>
        {info.categories.map((c) => {
          const block = why(c);
          const on = v.script_categories.includes(c.id);
          return (
            <Check key={c.id} checked={on} disabled={!!block && !on} onChange={(x) => set({ script_categories: toggle(v.script_categories, c.id, x) })}>
              <code>{c.id}</code><small className="nm-cat">{block || t(`nm.c.${c.id}`)}</small>
            </Check>
          );
        })}
      </div>
      <ScriptPicker v={v} set={set} t={t} />
      <ScriptArgs v={v} set={set} info={info} t={t} />
      <Num label={t("nm.scriptTimeout")} value={v.script_timeout_s} min={1} max={3600} placeholder={t("nm.noLimit")} onChange={(script_timeout_s) => set({ script_timeout_s })} />
    </div>
  );
}

let scriptCache = null; // katalog NSE nie zmienia się w trakcie sesji

function ScriptPicker({ v, set, t }) {
  const [all, setAll] = useState(scriptCache);
  const [q, setQ] = useState("");
  useEffect(() => {
    if (all) return;
    let live = true;
    api.nmapScripts().then((d) => { scriptCache = d; if (live) setAll(d); }).catch(() => {});
    return () => { live = false; };
  }, [all]);
  const hits = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle || !all) return [];
    return all.filter((s) => (s.name.includes(needle) || s.categories.includes(needle)) && !v.scripts.includes(s.name)).slice(0, 8);
  }, [q, all, v.scripts]);
  const add = (name) => { set({ scripts: [...v.scripts, name] }); setQ(""); };
  return (
    <div className="span-2 field">
      <label htmlFor="nm-script">{t("nm.scripts")}</label>
      {v.scripts.length > 0 && (
        <ul className="nm-chips">
          {v.scripts.map((s) => (
            <li key={s} className="chip mono">
              <a href={`https://nmap.org/nsedoc/scripts/${s}.html`} target="_blank" rel="noopener noreferrer">{s}</a>
              <button type="button" onClick={() => set({ scripts: v.scripts.filter((x) => x !== s) })} aria-label={t("nm.removeScript", { name: s })}><X size={12} aria-hidden="true" /></button>
            </li>
          ))}
        </ul>
      )}
      <input id="nm-script" className="mono" type="search" value={q} spellCheck={false} autoComplete="off"
             placeholder={all ? t("nm.scriptsPh", { n: all.length }) : "…"} onChange={(e) => setQ(e.target.value)}
             onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); if (hits[0]) add(hits[0].name); } }} />
      {q.trim() && all && (
        <ul className="nm-hits">
          {hits.map((s) => (
            <li key={s.name}>
              <button type="button" onClick={() => add(s.name)}><code>{s.name}</code><small>{s.categories.join(", ")}</small></button>
            </li>
          ))}
          {!hits.length && <li className="quiet nm-nohit">{t("nm.noScript")}</li>}
        </ul>
      )}
    </div>
  );
}

function ScriptArgs({ v, set, info, t }) {
  const used = Object.keys(v.script_args);
  const free = info.script_args.filter((k) => !used.includes(k));
  const put = (k, val) => set({ script_args: { ...v.script_args, [k]: val } });
  const drop = (k) => { const { [k]: _, ...rest } = v.script_args; set({ script_args: rest }); };
  return (
    <div className="span-2 field">
      <label htmlFor="nm-arg">{t("nm.args")}</label>
      {used.map((k) => (
        <div className="nm-arg" key={k}>
          <code>{k}</code>
          <input className="mono" value={v.script_args[k]} aria-label={k} spellCheck={false} onChange={(e) => put(k, e.target.value)} />
          <button type="button" className="icon-btn sm" onClick={() => drop(k)} aria-label={t("nm.removeArg", { name: k })}><X size={13} aria-hidden="true" /></button>
        </div>
      ))}
      <select id="nm-arg" value="" onChange={(e) => e.target.value && put(e.target.value, "")}>
        <option value="">{t("nm.addArg")}</option>
        {free.map((k) => <option key={k} value={k}>{k}</option>)}
      </select>
    </div>
  );
}

function Speed({ v, set, t }) {
  return (
    <div className="form-grid">
      <Select label={t("nm.timing")} value={v.timing} onChange={(x) => set({ timing: +x })} options={[0, 1, 2, 3, 4, 5].map((i) => [i, t(`nm.T${i}`)])} />
      <Num label={t("nm.retries")} value={v.max_retries} min={0} max={20} placeholder={t("nm.byTiming")} onChange={(max_retries) => set({ max_retries })} />
      <Num label={t("nm.hostTimeout")} value={v.host_timeout_s} min={10} max={86400} placeholder={t("nm.noLimit")} onChange={(host_timeout_s) => set({ host_timeout_s })} />
      <Num label={t("nm.delay")} value={v.scan_delay_ms} min={1} max={60000} placeholder={t("nm.byTiming")} onChange={(scan_delay_ms) => set({ scan_delay_ms })} />
      <Num label={t("nm.minRate")} hint={t("nm.minRateHint")} value={v.min_rate} min={1} max={10000} placeholder={t("nm.noLimit")} onChange={(min_rate) => set({ min_rate })} />
      <Num label={t("nm.parallel")} value={v.max_parallelism} min={1} max={1000} placeholder={t("nm.byTiming")} onChange={(max_parallelism) => set({ max_parallelism })} />
    </div>
  );
}

function Packets({ v, set, info, t }) {
  const off = !info.raw;
  return (
    <div className="form-grid">
      <p className="span-2 quiet nm-empty">{t(off ? "nm.pktNoRaw" : "nm.pktHint")}</p>
      <Num label={`${t("nm.mtu")} (--mtu)`} value={v.mtu} min={8} max={1496} step={8} disabled={off || v.fragment} placeholder={t("nm.off")} onChange={(mtu) => set({ mtu })} />
      <Num label={`${t("nm.srcPort")} (--source-port)`} value={v.source_port} min={1} max={65535} disabled={off} placeholder={t("nm.random")} onChange={(source_port) => set({ source_port })} />
      <Num label={`${t("nm.dataLen")} (--data-length)`} value={v.data_length} min={1} max={1400} disabled={off} placeholder={t("nm.off")} onChange={(data_length) => set({ data_length })} />
      <Num label="TTL (--ttl)" value={v.ttl} min={1} max={255} disabled={off} placeholder={t("nm.random")} onChange={(ttl) => set({ ttl })} />
      <div className="span-2 nm-checks">
        <Check checked={v.fragment} disabled={off || v.mtu != null} onChange={(fragment) => set({ fragment })}>{t("nm.fragment")} <Flag>-f</Flag></Check>
        <Check checked={v.badsum} disabled={off} onChange={(badsum) => set({ badsum })}>{t("nm.badsum")} <Flag>--badsum</Flag></Check>
      </div>
    </div>
  );
}

const PANELS = { hosts: Hosts, ports: Ports, tech: Tech, svc: Services, nse: Nse, speed: Speed, pkt: Packets };

// ---------- podgląd komendy ----------
function Preview({ value, rate, intel }) {
  const { t, n, dur } = useI18n();
  const [state, setState] = useState({ data: null, error: null });
  const [copied, setCopied] = useState(false);
  const key = JSON.stringify([value, rate, intel]);
  useEffect(() => {
    let live = true;
    const h = setTimeout(() => {
      api.nmapPreview({ options: value, rate_limit: rate, intel })
        .then((data) => live && setState({ data, error: null }))
        .catch((e) => live && setState((s) => ({ ...s, error: e.message })));
    }, 250);
    return () => { live = false; clearTimeout(h); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  const { data, error } = state;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(`${data.command} ${t("nm.targetsArg")}`);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (e) { /* brak dostępu do schowka: komendę da się zaznaczyć ręcznie */ }
  };
  return (
    <div className="nm-cmd" aria-busy={!data && !error}>
      <div className="nm-cmd-head">
        <span>{t("nm.command")}</span>
        {data && !error && (
          <button type="button" className="link nm-copy" onClick={copy}>
            <Copy size={12} aria-hidden="true" /> <span aria-live="polite">{t(copied ? "nm.copied" : "nm.copy")}</span>
          </button>
        )}
      </div>
      {error ? <p className="form-error" role="alert">{error}</p> : data ? (
        <>
          {data.prescan && <Command text={data.prescan} />}
          <Command text={data.command}><span className="quiet">{t("nm.targetsArg")}</span></Command>
          <p className="nm-facts">
            {data.prescan ? t("nm.factsPre", { n: n(data.probes) }) : t("nm.facts", { n: n(data.probes), d: data.min_seconds < 1 ? "<1 s" : dur(data.min_seconds), r: n(rate) })}
            {data.dropped.length > 0 && <> {t("nm.dropped", { f: data.dropped.join(" ") })}</>}
          </p>
        </>
      ) : <span className="skel-line" aria-hidden="true" />}
    </div>
  );
}
