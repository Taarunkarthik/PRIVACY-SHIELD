import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: { '/api': { target: 'http://127.0.0.1:8000', changeOrigin: false } },
  },
  build: {
    rollupOptions: {
      output: { manualChunks: { charts: ['recharts'] } },
    },
  },
  test: {
    environment: 'jsdom',
    include: ['tests/*.test.ts', 'tests/*.test.tsx'],
    setupFiles: ['./tests/setup.ts'],
    clearMocks: true,
    restoreMocks: true,
    testTimeout: 15000,
  },
});
