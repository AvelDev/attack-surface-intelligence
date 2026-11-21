import { useEffect, useState } from "react";

/* Routing na hashu (#/skany/12): backend serwuje tylko "/", więc nie trzeba catch-all po stronie
   FastAPI, a odświeżenie dowolnego ekranu dalej działa. */
function parse() {
  const parts = window.location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  return { screen: parts[0] || "overview", arg: parts[1] || null };
}

export function useRoute() {
  const [route, setRoute] = useState(parse);
  useEffect(() => {
    const on = () => setRoute(parse());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

export const href = (screen, arg) => (screen === "overview" ? "#/" : `#/${screen}${arg != null ? `/${arg}` : ""}`);
export const go = (screen, arg) => { window.location.hash = href(screen, arg).slice(1); };
