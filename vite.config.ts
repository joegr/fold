import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Vite config for the fold frontend.
//
// Kept intentionally small:
//   * build.outDir = 'build' so the existing Dockerfile stage-2 copy
//     (`COPY --from=frontend /build/build ./build/`) is unchanged.
//   * server.proxy forwards /api to the Flask backend during `npm run dev`.
//     In production the backend serves the built static assets directly, so
//     this proxy is only relevant for local dev.
//   * No legacy browser transforms are configured; Vite's default ESM output
//     targets evergreen browsers. Add `build.target` if you need wider support.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'build',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 3000,
    strictPort: false,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: false,
        secure: false,
      },
    },
  },
  preview: {
    port: 3000,
  },
});
