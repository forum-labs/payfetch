import { defineConfig } from "vitest/config";

// Scoped to this adapter's own tests. It imports payfetch source and the shared
// payfetch test fakes from the repo root via relative paths; vitest resolves and
// transforms those directly (Node-side, no fs.allow restriction).
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
  },
});
