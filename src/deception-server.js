import express from 'express';
import { fileURLToPath } from 'url';
import { resolve } from 'path';
import { config } from './config.js';
import * as db from './db.js';

const app = express();
const { delayMs } = config.deception;

app.set('trust proxy', true);

app.use(express.raw({ type: () => true, limit: '8kb' }));

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = String(forwarded).split(',')[0].trim();
    if (first) return first;
  }
  const realIp = req.headers['x-real-ip'];
  if (realIp) return String(realIp).trim();
  return req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || '';
}

app.use(async (req, res, next) => {
  const ip = getClientIp(req);
  const path = req.path || req.url?.split('?')[0] || '';
  const query = req.url?.includes('?') ? req.url.slice(req.url.indexOf('?') + 1) : '';
  const ua = req.get('user-agent') || '';
  const bodyPreview = (req.body && Buffer.isBuffer(req.body)) ? req.body.slice(0, 512).toString('utf8').replace(/\0/g, '') : '';
  try {
    db.logDeceptionHit(req.method, path, query, ip, ua, bodyPreview);
  } catch (_) {}
  if (delayMs > 0) {
    await new Promise((r) => setTimeout(r, delayMs));
  }
  next();
});

function fakePasswd() {
  return `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:999:999:MySQL Server:/var/lib/mysql:/bin/false
`;
}

function fakeShell(cmd) {
  if (/whoami|id\s|id$/.test(cmd)) {
    return 'www-data\n';
  }
  if (/ifconfig|ip\s|ipconfig/.test(cmd)) {
    return 'eth0: inet 10.0.0.99  netmask 255.255.255.0\n';
  }
  if (/uname|hostname/.test(cmd)) {
    return 'prod-web-01\n';
  }
  return 'ok\n';
}

function fakePhpInfo() {
  return `<!DOCTYPE html><html><head><title>phpinfo()</title></head><body>
<h1>PHP Version 7.4.3</h1>
<table><tr><td>System</td><td>Linux prod-web-01 5.4.0</td></tr>
<tr><td>Server API</td><td>FPM/FastCGI</td></tr></table>
</body></html>`;
}

function fakeSql() {
  return JSON.stringify({
    error: false,
    rows: [{ id: 1, name: 'admin', created: '2024-01-01 00:00:00' }],
  });
}

function fakeJndi() {
  return '';
}

function fakeDefault() {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Login</title></head>
<body><h1>Sign In</h1>
<form method="post" action="/login">
<input name="user" placeholder="Username">
<input name="pass" type="password" placeholder="Password">
<button type="submit">Login</button>
</form>
<!-- build:prod -->
</body></html>`;
}

function chooseResponse(req) {
  const path = (req.path || '').toLowerCase();
  const query = (req.url || '').toLowerCase();
  const raw = path + query + (req.body && Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '');

  if (/\/etc\/passwd|passwd|etc%2fpasswd|\.\.%2f|\.\.\//.test(raw)) {
    return { body: fakePasswd(), type: 'text/plain' };
  }
  if (/whoami|id\s|ifconfig|ipconfig|cmd\.exe|powershell|bin%2fsh|bin%2fbash|%2fbin%2fsh/.test(raw)) {
    const cmd = (query + path).slice(-80);
    return { body: fakeShell(cmd), type: 'text/plain' };
  }
  if (/phpinfo|eval\s*\(|system\s*\(|exec\s*\(|passthru|shell_exec|popen|proc_open/.test(raw)) {
    return { body: fakePhpInfo(), type: 'text/html' };
  }
  if (/union.*select|base64_decode|0x[0-9a-f]+|select\s+.*from|insert\s+into/.test(raw)) {
    return { body: fakeSql(), type: 'application/json' };
  }
  if (/\$\{jndi:|%24%7bjndi|jndi%3a|ldap%3a/.test(raw)) {
    return { body: fakeJndi(), type: 'application/octet-stream' };
  }
  return { body: fakeDefault(), type: 'text/html' };
}

app.all('*', (req, res) => {
  const { body, type } = chooseResponse(req);
  res.setHeader('X-Powered-By', 'PHP/7.4.3');
  res.setHeader('Content-Type', type);
  res.status(200).send(body);
});

export { app as deceptionApp };

const __filename = fileURLToPath(import.meta.url);
const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(__filename);
if (isMain) {
  const { port, bindHost } = config.deception;
  app.listen(port, bindHost, () => {
    console.log(`[誘騙服務] 假系統監聽 http://${bindHost}:${port}（供 Nginx proxy 導向）`);
  });
}
