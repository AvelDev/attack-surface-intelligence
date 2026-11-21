import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev: `npm run dev` + FastAPI na :8000 (proxy /api). Build: frontend/dist, serwowany przez FastAPI pod "/".
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": "http://127.0.0.1:8000", "/legacy": "http://127.0.0.1:8000", "/command-center": "http://127.0.0.1:8000" },
  },
  build: { outDir: "dist", assetsDir: "assets", sourcemap: false },
});
