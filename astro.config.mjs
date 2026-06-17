import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
  site: 'https://trytrustchecker.com',
  integrations: [sitemap()],
  adapter: cloudflare(),
});
