import https from 'https';
import http from 'http';
import { config } from './config.js';

const VYOS = config.vyos;

function getFormBody(op, path, key) {
  const form = new URLSearchParams();
  form.set('key', key || VYOS.apiKey);
  form.set('data', JSON.stringify({ op, path }));
  return form.toString();
}

function requestWithNode(url, body, options = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const isHttps = u.protocol === 'https:';
    const lib = isHttps ? https : http;
    const agentOpts = isHttps && !VYOS.rejectUnauthorized
      ? { rejectUnauthorized: false }
      : {};
    const req = lib.request(
      url,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        ...(isHttps && Object.keys(agentOpts).length ? { agent: new https.Agent(agentOpts) } : {}),
      },
      (res) => {
        let text = '';
        res.on('data', (chunk) => { text += chunk; });
        res.on('end', () => {
          try {
            const data = JSON.parse(text);
            if (!data.success) reject(new Error(data.error || text || 'VyOS API 失敗'));
            else resolve(data);
          } catch (_) {
            reject(new Error(`VyOS API 非 JSON: ${text.slice(0, 200)}`));
          }
        });
      }
    );
    req.on('error', (err) => {
      const msg = err.code === 'ECONNREFUSED'
        ? '連線被拒絕（請確認 VYOS_URL、VyOS 是否啟用 API、防火牆）'
        : err.code === 'ENOTFOUND'
          ? '無法解析主機（請確認 VYOS_URL）'
          : err.code === 'ETIMEDOUT' || err.code === 'ECONNRESET'
            ? '連線逾時或中斷'
            : err.message;
      reject(new Error(`VyOS 連線失敗: ${msg}`));
    });
    req.setTimeout(15000, () => {
      req.destroy();
      reject(new Error('VyOS 連線逾時'));
    });
    req.write(body);
    req.end();
  });
}

async function request(op, path, options = {}) {
  const url = `${VYOS.baseUrl.replace(/\/$/, '')}/configure`;
  const body = getFormBody(op, path, options.apiKey || VYOS.apiKey);
  try {
    return await requestWithNode(url, body, options);
  } catch (err) {
    throw err;
  }
}

export async function addBlackhole(cidr) {
  const path = ['protocols', 'static', 'route', cidr, 'blackhole'];
  return request('set', path);
}

export async function deleteBlackhole(cidr) {
  const path = ['protocols', 'static', 'route', cidr, 'blackhole'];
  return request('delete', path);
}

export async function getStaticRoutes(apiKey) {
  const url = `${VYOS.baseUrl.replace(/\/$/, '')}/retrieve`;
  const form = new URLSearchParams();
  form.set('key', apiKey || VYOS.apiKey);
  form.set('data', JSON.stringify({ op: 'showConfig', path: ['protocols', 'static'] }));
  const data = await requestWithNode(url, form.toString());
  return data.data;
}

export { request };
