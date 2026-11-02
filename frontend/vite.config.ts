import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"
import { noInlineStyles } from "./src/lib/no-inline-styles.ts"

export default defineConfig({
  // noInlineStyles: no library puts a <style> element into the page – the CSP allows none (src/lib/no-inline-styles.ts)
  plugins: [noInlineStyles(), react(), tailwindcss()],
  server: {
    // npm run dev: the API of a running container (docker compose up) or of `uvicorn app.main:app --port 8095`
    proxy: { "/api": process.env.NEWS_API ?? "http://127.0.0.1:8095" },
  },
  // the app ~770 kB (~230 kB gzipped); sign-in/setup, settings and each language are chunks of their own
  build: { chunkSizeWarningLimit: 900 },
  resolve: {
    alias: { "@": `${import.meta.dirname}/src` },
  },
})
