import { defineConfig } from "vite";

// Config for the informational side-channel probes under analysis/.
// Kept out of the normal `npm test` run (vitest.config.ts). Run with:
//   npm run analysis:timing
export default defineConfig({
  test: {
    include: "analysis/*.js"
  }
});
