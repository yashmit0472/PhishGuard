import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
// Development uses `vite build --watch`; the authenticated Python server serves dist.
export default defineConfig({plugins:[react()],server:{host:'127.0.0.1'},preview:{host:'127.0.0.1'}});
