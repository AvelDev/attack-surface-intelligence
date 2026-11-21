import { LayoutDashboard, Network, ShieldAlert, FileCode2, CalendarClock, Users, Plug, Radar } from "lucide-react";
import { useI18n } from "../i18n.jsx";
import { can } from "../api.js";
import { href } from "../router.js";

const NAV = [
  { screen: "overview", key: "nav.overview", icon: LayoutDashboard },
  { screen: "scans", key: "nav.ranges", icon: Network },
  { screen: "findings", key: "nav.findings", icon: ShieldAlert },
  { screen: "signatures", key: "nav.signatures", icon: FileCode2 },
  { screen: "schedule", key: "nav.schedule", icon: CalendarClock },
  { screen: "settings", key: "nav.settings", icon: Plug },
  { screen: "users", key: "nav.users", icon: Users, role: "admin" },
  { key: "nav.cc", icon: Radar, external: "/command-center", sep: true },
];

export default function Shell({ user, screen, theme, onTheme, onLogout, children }) {
  const { t } = useI18n();
  return (
    <div className="shell">
      <a className="skip" href="#main">{t("nav.skip")}</a>
      <nav className="rail" aria-label="ASI">
        <ul>
          {NAV.filter((n) => !n.role || can(user, n.role)).map((n) => {
            const Icon = n.icon;
            const label = t(n.key);
            const current = n.screen === screen;
            return (
              <li key={n.key} className={n.sep ? "rail-sep" : undefined}>
                <a
                  href={n.external || href(n.screen)}
                  className={`rail-link${current ? " is-current" : ""}`}
                  aria-current={current ? "page" : undefined}
                  aria-label={n.external ? `${label}: ${t("nav.legacy")}` : label}
                >
                  <Icon size={19} strokeWidth={1.6} aria-hidden="true" />
                  <span className="rail-tip" aria-hidden="true">
                    {label}
                    {n.external && <small>{t("nav.legacy")}</small>}
                  </span>
                </a>
              </li>
            );
          })}
        </ul>
      </nav>
      <div className="col">{children({ user, theme, onTheme, onLogout })}</div>
    </div>
  );
}
