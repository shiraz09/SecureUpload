import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [
    react(),        // Vite’s React plugin
    tailwindcss(),  // Tailwind plugin
  ],
});
