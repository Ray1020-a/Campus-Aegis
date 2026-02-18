import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import geoip from 'geoip-lite';
import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { addBlackhole, deleteBlackhole, getStaticRoutes } from './vyos-client.js';
import * as db from './db.js';
import { config } from './config.js';
import { deceptionApp } from './deception-server.js';
import { flagFromCountryCode, countryName } from './admin-views.js';
import { state, getUptimeSeconds } from './state.js';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const pkg = require('../package.json');

const __dirname = dirname(fileURLToPath(import.meta.url));
const panelHtml = readFileSync(join(__dirname, 'admin-panel.html'), 'utf8');

const loginAttempts = new Map();
const LOGIN_RATE_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 5;
function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
}
function isLoginRateLimited(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry) return false;
  if (now >= entry.resetAt) {
    loginAttempts.delete(ip);
    return false;
  }
  return entry.count >= LOGIN_MAX_ATTEMPTS;
}
function recordLoginFailure(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, resetAt: now + LOGIN_RATE_WINDOW_MS };
  entry.count++;
  if (entry.count === 1) entry.resetAt = now + LOGIN_RATE_WINDOW_MS;
  loginAttempts.set(ip, entry);
}
function recordLoginSuccess(ip) {
  loginAttempts.delete(ip);
}

export function createApp(aggregator = null) {
  const app = express();

  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
  });
  app.use(cookieParser());
  app.use(express.json());
  app.use(
    session({
      secret: config.admin.sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: { httpOnly: true, maxAge: 24 * 60 * 60 * 1000, sameSite: 'lax' },
    })
  );

  function requireAuth(req, res, next) {
    if (req.path === '/login' || req.path === '/api/login') return next();
    if (req.path === '/api/health') return next();
    if (req.session?.authenticated) return next();
    if (req.path.startsWith('/api/')) return res.status(401).json({ success: false, error: '未登入' });
    return res.redirect('/login');
  }
  app.use(requireAuth);

  app.get('/api/health', async (req, res) => {
    try {
      let dbOk = false;
      try {
        db.getDb().prepare('SELECT 1').get();
        dbOk = true;
      } catch (_) {}
      let vyosOk = false;
      try {
        await Promise.race([
          getStaticRoutes().then(() => { vyosOk = true; }),
          new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 5000)),
        ]);
      } catch (_) {}
      const status = dbOk ? (vyosOk ? 'ok' : 'degraded') : 'error';
      res.json({
        success: true,
        data: {
          status,
          db: dbOk,
          vyos: vyosOk,
          netflowReceived: state.netflowReceived,
          lastDefenseAt: state.lastDefenseAt,
          lastDefenseResult: state.lastDefenseResult,
          uptimeSeconds: getUptimeSeconds(),
          version: pkg.version || '1.0.0',
        },
      });
    } catch (e) {
      res.status(500).json({ success: false, error: String(e.message) });
    }
  });

  app.get('/login', (req, res) => {
    if (req.session?.authenticated) return res.redirect('/');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(panelHtml);
  });

  app.post('/api/login', (req, res) => {
    const ip = getClientIp(req);
    if (isLoginRateLimited(ip)) {
      return res.status(429).json({ success: false, error: '登入嘗試過於頻繁，請 15 分鐘後再試' });
    }
    const pwd = req.body?.password ?? '';
    const expected = config.admin.password;
    if (!expected) {
      return res.status(500).json({ success: false, error: '未設定 ADMIN_PASSWORD' });
    }
    if (pwd !== expected) {
      recordLoginFailure(ip);
      return res.status(401).json({ success: false, error: '密碼錯誤' });
    }
    recordLoginSuccess(ip);
    req.session.authenticated = true;
    res.json({ success: true });
  });

  app.post('/api/logout', (req, res) => {
    req.session.destroy(() => {});
    res.json({ success: true });
  });

  app.get('/api/stats', (req, res) => {
    try {
      const active = db.listActiveBlackholes();
      const blackholeByDay = db.getBlackholeStatsByDay(14);
      const deceptionByDay = db.getDeceptionStatsByDay(14);
      const topIps = db.getTopDeceptionIps(15);
      const totalBlackholeLogs = db.getDb().prepare('SELECT COUNT(*) as c FROM blackhole_log').get();
      const totalDeception = db.getDb().prepare('SELECT COUNT(*) as c FROM deception_log').get();
      const deceptionToday = db.getDb()
        .prepare("SELECT COUNT(*) as c FROM deception_log WHERE date(created_at) = date('now')")
        .get();
      const deception7d = db.getDb()
        .prepare("SELECT COUNT(*) as c FROM deception_log WHERE created_at >= datetime('now', '-7 days')")
        .get();
      const topIpsWithGeo = topIps.map((r) => {
        const geo = geoip.lookup(r.ip);
        const countryCode = geo?.country ?? 'XX';
        return { ...r, countryCode, country: countryName(countryCode), flag: flagFromCountryCode(countryCode) };
      });
      res.json({
        success: true,
        data: {
          activeBlackholes: active.length,
          totalBlackholeLogs: totalBlackholeLogs?.c ?? 0,
          totalDeception: totalDeception?.c ?? 0,
          deceptionToday: deceptionToday?.c ?? 0,
          deception7d: deception7d?.c ?? 0,
          blackholeByDay,
          deceptionByDay,
          topDeceptionIps: topIpsWithGeo,
          system: {
            version: pkg.version || '1.0.0',
            uptimeSeconds: getUptimeSeconds(),
            lastDefenseAt: state.lastDefenseAt,
            lastDefenseResult: state.lastDefenseResult,
            netflowReceived: state.netflowReceived,
          },
        },
      });
    } catch (e) {
      res.status(500).json({ success: false, error: String(e.message) });
    }
  });

  app.get('/api/blackholes', (req, res) => {
    try {
      const list = db.listActiveBlackholes();
      res.json({ success: true, data: list });
    } catch (e) {
      res.status(500).json({ success: false, error: String(e.message) });
    }
  });

  app.post('/api/blackholes/revoke', async (req, res) => {
    const cidr = req.body?.cidr;
    if (!cidr || typeof cidr !== 'string') {
      return res.status(400).json({ success: false, error: '請提供 cidr' });
    }
    const normalized = cidr.includes('/') ? cidr : `${cidr}/32`;
    try {
      await deleteBlackhole(normalized);
      db.revokeBlackhole(normalized, req.body?.revoked_by || 'admin');
      res.json({ success: true, message: `已撤銷黑洞 ${normalized}` });
    } catch (e) {
      res.status(500).json({ success: false, error: String(e.message) });
    }
  });

  app.get('/api/logs', (req, res) => {
    try {
      const limit = parseInt(req.query.limit, 10) || 200;
      const list = db.listAllLogs(limit);
      const withGeo = list.map((r) => {
        const ip = (r.cidr || '').split('/')[0];
        const geo = ip ? geoip.lookup(ip) : null;
        const cc = geo?.country ?? 'XX';
        return { ...r, countryCode: cc, country: countryName(cc), flag: flagFromCountryCode(cc) };
      });
      res.json({ success: true, data: withGeo });
    } catch (e) {
      res.status(500).json({ success: false, error: String(e.message) });
    }
  });

  app.get('/api/deception-logs', (req, res) => {
    try {
      const limit = parseInt(req.query.limit, 10) || 100;
      const list = db.listDeceptionLogs(limit);
      const withGeo = list.map((r) => {
        const geo = geoip.lookup(r.ip);
        const cc = geo?.country ?? 'XX';
        return { ...r, countryCode: cc, country: countryName(cc), flag: flagFromCountryCode(cc) };
      });
      res.json({ success: true, data: withGeo });
    } catch (e) {
      res.status(500).json({ success: false, error: String(e.message) });
    }
  });

  app.post('/api/data/clear', async (req, res) => {
    try {
      const active = db.listActiveBlackholes();
      for (const row of active) {
        try {
          await deleteBlackhole(row.cidr);
        } catch (_) {}
      }
      db.clearAllData();
      res.json({ success: true, message: '已刪除所有數據，並已從 VyOS 撤銷所有黑洞' });
    } catch (e) {
      res.status(500).json({ success: false, error: String(e.message) });
    }
  });

  app.post('/api/data/clear-logs-only', (req, res) => {
    try {
      db.clearAllData();
      res.json({ success: true, message: '已刪除所有黑洞日誌與誘騙日誌，VyOS 黑洞已保留' });
    } catch (e) {
      res.status(500).json({ success: false, error: String(e.message) });
    }
  });

  app.get('/api/netflow/recent', (req, res) => {
    try {
      if (!aggregator) {
        return res.json({
          success: true,
          data: [],
          hint: '請使用單一進程啟動（npm run start:full）以顯示 NetFlow 即時流量。',
        });
      }
      const limit = Math.min(parseInt(req.query.limit, 10) || 200, 500);
      const list = aggregator.getRecentFlows().slice(0, limit);
      res.json({ success: true, data: list });
    } catch (e) {
      res.status(500).json({ success: false, error: String(e.message) });
    }
  });

  app.get('/', (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(panelHtml);
  });

  return app;
}

const { port, bindHost } = config.admin;
const { port: decPort, bindHost: decBind } = config.deception;

const isStandalone = process.argv[1] && process.argv[1].includes('admin-server');
if (isStandalone) {
  const app = createApp(null);
  app.listen(port, bindHost, () => {
    console.log(`管理員面板 http://${bindHost}:${port}`);
  });
  deceptionApp.listen(decPort, decBind, () => {
    console.log(`[誘騙服務] 假系統監聽 http://${decBind}:${decPort}（供 Nginx proxy 導向）`);
  });
}
