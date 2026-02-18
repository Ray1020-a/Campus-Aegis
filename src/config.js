import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadEnv() {
  try {
    const p = join(__dirname, '..', '.env');
    const content = readFileSync(p, 'utf8');
    for (const line of content.split('\n')) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
      if (m) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '').trim();
    }
  } catch (_) {}
}
loadEnv();

const dbPathRaw = process.env.DB_PATH || 'data/defense.db';
const dbPathResolved = dbPathRaw.startsWith('/') ? dbPathRaw : resolve(process.cwd(), dbPathRaw);

export const config = {
  vyos: {
    baseUrl: process.env.VYOS_URL || 'https://192.168.1.1',
    apiKey: process.env.VYOS_API_KEY || '',
    rejectUnauthorized: process.env.VYOS_INSECURE !== '1',
  },

  netflow: {
    enabled: (process.env.NETFLOW_ENABLED || '1') === '1',
    port: parseInt(process.env.NETFLOW_PORT || '2055', 10),
    bindHost: process.env.NETFLOW_BIND || '0.0.0.0',
  },

  pcap: {
    enabled: (process.env.PCAP_ENABLED || '0') === '1',
    interface: process.env.PCAP_INTERFACE || 'eth0',
  },

  gemini: {
    apiKey: process.env.GEMINI_API_KEY || '',
    model: process.env.GEMINI_MODEL || 'gemini-2.0-flash',
    intervalSeconds: parseInt(process.env.DEFENSE_INTERVAL_SECONDS || '120', 10),
  },

  db: {
    path: dbPathResolved,
  },
  admin: {
    port: parseInt(process.env.ADMIN_PORT || '3000', 10),
    bindHost: process.env.ADMIN_BIND || '0.0.0.0',
    password: process.env.ADMIN_PASSWORD || '',
    sessionSecret: process.env.ADMIN_SESSION_SECRET || process.env.ADMIN_PASSWORD || 'change-me-in-production',
  },

  deception: {
    port: parseInt(process.env.DECEPTION_PORT || '3099', 10),
    bindHost: process.env.DECEPTION_BIND || '127.0.0.1',
    delayMs: parseInt(process.env.DECEPTION_DELAY_MS || '0', 10),
  },
};

export function validateConfig(options = {}) {
  const errors = [];
  if (!config.vyos.baseUrl || config.vyos.baseUrl === 'https://192.168.1.1') {
    errors.push('請在 .env 設定 VYOS_URL（VyOS 的 HTTPS 位址）');
  }
  if (!config.vyos.apiKey) {
    errors.push('請在 .env 設定 VYOS_API_KEY');
  }
  if (!config.gemini.apiKey) {
    errors.push('請在 .env 設定 GEMINI_API_KEY');
  }
  if (!options.skipAdminPassword && !config.admin.password) {
    errors.push('請在 .env 設定 ADMIN_PASSWORD（管理員面板登入密碼）');
  }
  if (errors.length) {
    throw new Error('設定驗證失敗：\n' + errors.join('\n'));
  }
}
