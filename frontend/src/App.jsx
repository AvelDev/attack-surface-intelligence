import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "./api.js";
import { useI18n } from "./i18n.jsx";
import Login from "./components/Login.jsx";
import Shell from "./components/Shell.jsx";
import Dashboard from "./components/Dashboard.jsx";
import Scans from "./screens/Scans.jsx";
import FindingsScreen from "./screens/FindingsScreen.jsx";
import Signatures from "./screens/Signatures.jsx";
import Schedule from "./screens/Schedule.jsx";
import Settings from "./screens/Settings.jsx";
import Users from "./screens/Users.jsx";
import { useRoute } from "./router.js";

const SCREENS = { scans: Scans, findings: FindingsScreen, signatures: Signatures, schedule: Schedule, settings: Settings, users: Users };

function readTheme() {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export default function App() {
  const { t } = useI18n();
  const [user, setUser] = useState(undefined); // undefined = sprawdzanie sesji
  const [theme, setTheme] = useState(readTheme);
  const { screen, arg } = useRoute();

  useEffect(() => {
    api.me().then(setUser).catch(() => setUser(null));
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme((cur) => {
      const next = cur === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem("asi.theme", next); } catch (e) { /* ignoruj */ }
      return next;
    });
  }, []);

  const onAuthLost = useCallback((err) => {
    if (err instanceof ApiError && err.status === 401) setUser(null);
  }, []);

  const logout = useCallback(async () => {
    try { await api.logout(); } catch (e) { /* sesja i tak wygasa */ }
    setUser(null);
  }, []);

  if (user === undefined) {
    return <div className="boot" role="status">{t("loading")}</div>;
  }
  if (!user) return <Login onLogin={setUser} theme={theme} onTheme={toggleTheme} />;

  return (
    <Shell user={user} screen={SCREENS[screen] ? screen : "overview"} theme={theme} onTheme={toggleTheme} onLogout={logout}>
      {(shell) => {
        const Screen = SCREENS[screen];
        return Screen
          ? <Screen key={screen} user={user} onAuthLost={onAuthLost} shell={shell} scanId={arg} />
          : <Dashboard user={user} onAuthLost={onAuthLost} shell={shell} />;
      }}
    </Shell>
  );
}
