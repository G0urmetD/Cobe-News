import { defineConfig } from "vitest/config"

// Unit tests for pure logic (paging, desktop notifications, sign-in state) – no browser, no server.
export default defineConfig({
  resolve: { alias: { "@": `${import.meta.dirname}/src` } },
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
    setupFiles: ["src/test-setup.ts"],
  },
})
