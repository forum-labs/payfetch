import { configDefaults, defineConfig } from "vitest/config";

/**
 * Root test config. The only change from vitest's defaults is excluding the
 * `adapters/` subpackages, each of which has its own package.json, node_modules
 * and test run (e.g. `adapters/agentkit`). Keeping them out of the root suite
 * means `npm test` here stays exactly the payfetch library suite and never
 * depends on an adapter's separately-installed dev/runtime deps.
 */
export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, "adapters/**"],
  },
});
