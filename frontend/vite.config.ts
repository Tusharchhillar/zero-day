import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    // Code-split the heavy chart + icon libs so the initial shell loads
    // fast; chart code is fetched only on the app pages. Vite 8 (rolldown)
    // expects manualChunks as a function.
    rolldownOptions: {
      output: {
        manualChunks(id: string) {
          if (id.includes('node_modules/recharts')) return 'charts';
          if (id.includes('node_modules/lucide-react')) return 'icons';
          if (id.includes('node_modules/react-router')) return 'router';
        },
      },
    },
  },
})