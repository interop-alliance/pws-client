import { defineConfig } from 'vitest/config'

/**
 * Vitest configuration, plus the dev server that Playwright drives for the
 * browser tests. The port is pinned (and `strictPort` set) so a dev server from
 * another project cannot silently answer the browser suite's requests. Every
 * dependency is pre-optimized from the library entry and the browser
 * fixtures, so a dependency first met mid-run cannot trigger a reload that
 * fails a dynamic import in flight.
 */
export default defineConfig({
  server: {
    port: 5183,
    strictPort: true
  },
  optimizeDeps: {
    entries: ['src/index.ts', 'test/browser/fixtures/*.ts']
  },
  test: {
    include: ['test/node/**/*.test.ts', 'src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts']
    }
  }
})
