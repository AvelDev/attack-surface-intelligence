export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function req(method, url, body) {
  const opts = { method, credentials: "same-origin", headers: {} };
  if (body instanceof FormData) {
    opts.body = body;
  } else if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(url, opts);
  } catch (e) {
    throw new ApiError(0, "brak połączenia z serwerem ASI");
  }
  let data = null;
  const text = await res.text();
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
  if (!res.ok) {
    const msg = (data && (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail))) || `HTTP ${res.status}`;
    throw new ApiError(res.status, msg);
  }
  return data;
}

export const api = {
  me: () => req("GET", "/api/me"),
  login: (username, password) => req("POST", "/api/login", { username, password }),
  logout: () => req("POST", "/api/logout"),
  dashboard: (range, scan) => {
    const q = new URLSearchParams();
    if (range) q.set("range", range);
    // scan: id przebiegu (widok zakresu) albo "at:<ts>" (suwak w widoku wszystkich zakresów)
    if (typeof scan === "string" && scan.startsWith("at:")) q.set("at", scan.slice(3));
    else if (range && scan) q.set("scan", scan);
    const s = q.toString();
    return req("GET", "/api/dashboard" + (s ? `?${s}` : ""));
  },
  triage: (item, status) =>
    req("POST", "/api/triage", { asset: item.asset, key: item.key, status, finding_rowid: item.finding_rowid ?? null }),
  note: (rangeId, note) => req("PUT", `/api/ranges/${rangeId}/note`, { note }),
  run: (rangeId) => req("POST", `/api/ranges/${rangeId}/run`),
  stop: (scanId) => req("POST", `/api/scans/${scanId}/stop`),
  resume: (scanId) => req("POST", `/api/scans/${scanId}/resume`),
  alerts: () => req("GET", "/api/alerts"),
  readAlerts: () => req("POST", "/api/alerts/read"),
  putApiKey: (key, value) => req("PUT", `/api/settings/${key}`, { value }),
  deleteApiKey: (key) => req("DELETE", `/api/settings/${key}`),
  tools: () => req("GET", "/api/tools"),
  scans: () => req("GET", "/api/scans"),
  scan: (id) => req("GET", `/api/scans/${id}`),
  scanTargets: (id) => req("GET", `/api/scans/${id}/targets`),
  startScan: (body) => req("POST", "/api/scans", body),
  importTargets: (form) => req("POST", "/api/scans/import-targets", form),
  importResults: (form) => req("POST", "/api/scans/import-results", form),
  nmap: () => req("GET", "/api/nmap"),
  nmapScripts: () => req("GET", "/api/nmap/scripts"),
  nmapPreview: (body) => req("POST", "/api/nmap/preview", body),
  scanNmap: (id) => req("GET", `/api/scans/${id}/nmap`),
  deleteScan: (id) => req("DELETE", `/api/scans/${id}`),
  scanToDojo: (id) => req("POST", `/api/scans/${id}/defectdojo`),
  editFinding: (rowid, body) => req("PATCH", `/api/findings/${rowid}`, body),
  signatures: () => req("GET", "/api/signatures"),
  addSignature: (body) => req("POST", "/api/signatures", body),
  updateSignature: (id, body) => req("PATCH", `/api/signatures/${id}`, body),
  deleteSignature: (id) => req("DELETE", `/api/signatures/${id}`),
  schedules: () => req("GET", "/api/schedules"),
  addSchedule: (body) => req("POST", "/api/schedules", body),
  deleteSchedule: (id) => req("DELETE", `/api/schedules/${id}`),
  settings: () => req("GET", "/api/settings"),
  saveDojo: (url, api_key) => req("POST", "/api/settings/defectdojo", { url, api_key }),
  saveGvm: (host, port, username, password) =>
    req("POST", "/api/settings/gvm", { host, port, username, password }),
  users: () => req("GET", "/api/users"),
  addUser: (body) => req("POST", "/api/users", body),
  deleteUser: (id) => req("DELETE", `/api/users/${id}`),
  exportDojo: (items) =>
    req("POST", "/api/defectdojo/export", {
      items: items.map((i) => ({ scan_id: i.scan_id, asset: i.asset, kind: i.kind, title: i.title, finding_rowid: i.finding_rowid ?? null })),
    }),
};

export const RANK = { read: 0, read_modify: 1, add_remove_modify: 2, admin: 3 };
export const can = (user, role) => !!user && RANK[user.role] >= RANK[role];
export const ROLES = ["read", "read_modify", "add_remove_modify", "admin"];
export const SEVS = ["critical", "high", "medium", "low", "info"];
export const isRunning = (status) => status === "running" || status === "queued";
