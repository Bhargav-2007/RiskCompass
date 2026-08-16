import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  base: '/RiskCompass/',
  plugins: [react()],
  test: { environment: 'jsdom', globals: true, setupFiles: './src/test/setup.ts' }
} as any)
