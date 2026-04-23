/**
 * Demo Mode — 所有外部依賴的離線 mock，由 DEMO_MODE=1 觸發
 */
import * as db from './db.js';

// ── Mock VyOS Client ────────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

export const mockVyosClient = {
  async addBlackhole(cidr) {
    await sleep(120 + Math.random() * 180);
    console.log(`[DEMO][VyOS] 模擬黑洞成功: ${cidr}`);
    return { success: true };
  },
  async deleteBlackhole(cidr) {
    await sleep(100 + Math.random() * 150);
    console.log(`[DEMO][VyOS] 模擬撤銷黑洞成功: ${cidr}`);
    return { success: true };
  },
  async getStaticRoutes() {
    await sleep(80);
    return { protocols: { static: {} } };
  },
};

// ── Mock Gemini Analyzer ────────────────────────────────────────────────────

const DEMO_MALICIOUS_IPS = [
  '185.220.101.47', '45.155.205.233', '194.165.16.78',
  '103.75.190.12',  '91.108.56.180',  '5.188.206.14',
  '78.128.113.233', '162.247.74.200', '198.96.155.3',
  '185.107.56.43',  '23.129.64.131',  '109.70.100.18',
];

export async function mockGeminiAnalyzer(flowSummary) {
  await sleep(1000 + Math.random() * 1500);

  if (!flowSummary.length) return [];

  // 優先找外網來源、高封包量（inbound 攻擊特徵）
  const isPrivate = (ip) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|140\.112\.)/.test(ip || '');
  const highTraffic = flowSummary
    .filter((f) => f.packets > 500 && !isPrivate(f.src))
    .map((f) => f.src)
    .filter((ip) => ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip));

  const candidates = highTraffic.length ? highTraffic : DEMO_MALICIOUS_IPS;

  const count = 1 + Math.floor(Math.random() * 3);
  const shuffled = [...candidates].sort(() => Math.random() - 0.5);
  const picked = [...new Set(shuffled.slice(0, count))];

  console.log(`[DEMO][Gemini] 模擬 AI 分析完成，建議黑洞: ${picked.join(', ')}`);
  return picked.map((ip) => `${ip}/32`);
}

// ── Demo NetFlow Generator ──────────────────────────────────────────────────

// 校園內網主機（學生/教職員電腦、IoT 設備等）
const INTERNAL_SRCS = [
  // 學生宿舍區 192.168.x
  '192.168.1.23',  '192.168.1.47',  '192.168.1.88',  '192.168.1.102',
  '192.168.2.15',  '192.168.2.63',  '192.168.2.134', '192.168.2.201',
  '192.168.3.9',   '192.168.3.77',
  // 教室/辦公室 10.x
  '10.0.1.12',     '10.0.1.34',     '10.0.1.89',     '10.0.2.5',
  '10.0.2.67',     '10.0.3.100',    '10.0.3.142',    '10.0.4.20',
  // 校園骨幹 172.16.x
  '172.16.0.55',   '172.16.0.88',   '172.16.1.10',   '172.16.1.200',
  // 校園公網 IP 段
  '140.112.30.5',  '140.112.30.18', '140.112.31.4',  '140.112.31.77',
];

// 常見外網目的（按真實流量加權：Google/CDN/社群/串流最多）
const EXTERNAL_DSTS_WEIGHTED = [
  // Google 服務（高頻）
  { ip: '142.250.185.46', dport: 443, proto: 'tcp' },   // google.com
  { ip: '142.250.196.110', dport: 443, proto: 'tcp' },  // googleapis
  { ip: '172.217.27.142', dport: 443, proto: 'tcp' },   // google.com
  { ip: '8.8.8.8',        dport: 53,  proto: 'udp' },   // Google DNS
  { ip: '8.8.4.4',        dport: 53,  proto: 'udp' },   // Google DNS
  // Cloudflare / CDN（高頻）
  { ip: '104.18.23.55',   dport: 443, proto: 'tcp' },
  { ip: '104.21.14.109',  dport: 443, proto: 'tcp' },
  { ip: '1.1.1.1',        dport: 53,  proto: 'udp' },   // Cloudflare DNS
  // YouTube / 串流
  { ip: '142.250.185.78', dport: 443, proto: 'tcp' },
  { ip: '74.125.68.91',   dport: 443, proto: 'tcp' },
  // Meta / Instagram
  { ip: '157.240.22.174', dport: 443, proto: 'tcp' },
  { ip: '157.240.3.174',  dport: 443, proto: 'tcp' },
  // Microsoft / Office 365
  { ip: '13.107.42.14',   dport: 443, proto: 'tcp' },
  { ip: '52.112.0.50',    dport: 443, proto: 'tcp' },
  // GitHub
  { ip: '140.82.121.4',   dport: 443, proto: 'tcp' },
  // npm / PyPI CDN
  { ip: '151.101.1.194',  dport: 443, proto: 'tcp' },
  { ip: '151.101.65.194', dport: 443, proto: 'tcp' },
  // LINE（台灣常用）
  { ip: '125.209.210.119', dport: 443, proto: 'tcp' },
  // 一般 HTTP（少量）
  { ip: '93.184.216.34',  dport: 80,  proto: 'tcp' },   // example.com
  { ip: '54.230.168.50',  dport: 80,  proto: 'tcp' },
];

// 校內伺服器（對外提供服務，會有外網打進來）
const INTERNAL_SERVERS = [
  { ip: '140.112.8.100', dport: 80,   proto: 'tcp' },   // 校網 web
  { ip: '140.112.8.101', dport: 443,  proto: 'tcp' },   // 校網 web HTTPS
  { ip: '140.112.8.200', dport: 25,   proto: 'tcp' },   // mail server
  { ip: '10.87.87.2',    dport: 80,   proto: 'tcp' },   // 內部 web
  { ip: '10.87.87.3',    dport: 3306, proto: 'tcp' },   // DB（內部）
  { ip: '10.87.87.4',    dport: 22,   proto: 'tcp' },   // SSH（內部）
];

// 外網攻擊來源
const ATTACK_SRCS = [
  '185.220.101.47', '45.155.205.233', '194.165.16.78',
  '103.75.190.12',  '91.108.56.180',  '5.188.206.14',
];

function randInt(min, max) {
  return min + Math.floor(Math.random() * (max - min + 1));
}
function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// 模擬 TCP 封包大小（HTTPS 瀏覽 vs DNS vs 大檔案下載）
function realisticBytes(dport, packets) {
  if (dport === 53) return randInt(60, 512);                        // DNS：小封包
  if (dport === 443) return packets * randInt(800, 1500);           // HTTPS：接近 MTU
  if (dport === 80)  return packets * randInt(400, 1200);
  return packets * randInt(200, 1000);
}

function generateFlowBatch(isAttackWindow) {
  const flows = [];
  const batchSize = randInt(8, 18);

  for (let i = 0; i < batchSize; i++) {
    const roll = Math.random();

    if (roll < 0.78) {
      // ── 78%：內網 → 外網（outbound）─ 最主要流量 ──────────────────
      const dst = pick(EXTERNAL_DSTS_WEIGHTED);
      const pkts = dst.dport === 53 ? randInt(1, 3) : randInt(3, 120);
      flows.push({
        src:      pick(INTERNAL_SRCS),
        dst:      dst.ip,
        sport:    randInt(1024, 65535),
        dport:    dst.dport,
        protocol: dst.proto,
        packets:  pkts,
        bytes:    realisticBytes(dst.dport, pkts),
      });

    } else if (roll < 0.90) {
      // ── 12%：內網 → 內網（內部橫向，印表機/NAS/DB 存取）─────────
      const srv = pick(INTERNAL_SERVERS);
      const pkts = randInt(2, 40);
      flows.push({
        src:      pick(INTERNAL_SRCS),
        dst:      srv.ip,
        sport:    randInt(1024, 65535),
        dport:    srv.dport,
        protocol: srv.proto,
        packets:  pkts,
        bytes:    realisticBytes(srv.dport, pkts),
      });

    } else {
      // ── 10%：外網 → 校內公開服務（正常入站，外部瀏覽校網）────────
      const srv = pick(INTERNAL_SERVERS.filter((s) => s.dport === 80 || s.dport === 443 || s.dport === 25));
      const pkts = randInt(3, 50);
      flows.push({
        src:      pick(EXTERNAL_DSTS_WEIGHTED).ip,
        dst:      srv.ip,
        sport:    randInt(1024, 65535),
        dport:    srv.dport,
        protocol: srv.proto,
        packets:  pkts,
        bytes:    realisticBytes(srv.dport, pkts),
      });
    }
  }

  if (isAttackWindow) {
    // 攻擊流量：外網 → 內網，高封包量掃描/DDoS 特徵
    const attacker = pick(ATTACK_SRCS);
    const target = pick(INTERNAL_SERVERS);
    for (let i = 0; i < randInt(8, 20); i++) {
      const pkts = randInt(500, 8000);
      flows.push({
        src:      attacker,
        dst:      target.ip,
        sport:    randInt(1024, 65535),
        dport:    pick([80, 443, 22, 3306, 53]),
        protocol: pick(['tcp', 'udp']),
        packets:  pkts,
        bytes:    pkts * randInt(60, 200),
      });
    }
  }
  return flows;
}

export function startDemoNetFlow(aggregator) {
  let tick = 0;
  const handle = setInterval(() => {
    tick++;
    const isAttack = tick % 15 === 0;
    const flows = generateFlowBatch(isAttack);
    for (const f of flows) aggregator.add(f);
    if (isAttack) {
      console.log('[DEMO][NetFlow] 模擬攻擊流量注入');
    }
  }, 2000);

  console.log('[DEMO][NetFlow] 假流量產生器已啟動（每 2 秒注入一批）');
  return {
    close: () => clearInterval(handle),
  };
}

// ── Seed Database ────────────────────────────────────────────────────────────

const SEED_BLACKHOLE_IPS = [
  { ip: '185.220.101.47', reason: 'gemini 判定', source: 'gemini' },
  { ip: '45.155.205.233', reason: 'gemini 判定', source: 'gemini' },
  { ip: '194.165.16.78',  reason: 'gemini 判定', source: 'gemini' },
  { ip: '103.75.190.12',  reason: 'gemini 判定', source: 'gemini' },
  { ip: '91.108.56.180',  reason: '管理員手動封鎖',  source: 'admin'  },
  { ip: '5.188.206.14',   reason: 'gemini 判定', source: 'gemini' },
  { ip: '78.128.113.233', reason: 'gemini 判定', source: 'gemini' },
  { ip: '162.247.74.200', reason: '管理員手動封鎖',  source: 'admin'  },
  { ip: '198.96.155.3',   reason: 'gemini 判定', source: 'gemini' },
  { ip: '185.107.56.43',  reason: 'gemini 判定', source: 'gemini' },
  { ip: '23.129.64.131',  reason: 'gemini 判定', source: 'gemini' },
  { ip: '109.70.100.18',  reason: 'gemini 判定', source: 'gemini' },
  { ip: '114.119.130.5',  reason: 'gemini 判定', source: 'gemini' },
  { ip: '222.186.42.117', reason: '管理員手動封鎖',  source: 'admin'  },
  { ip: '36.110.228.254', reason: 'gemini 判定', source: 'gemini' },
];

const DECEPTION_PATHS = [
  '/wp-login.php', '/phpmyadmin/', '/pma/', '/.env',
  '/admin/', '/login', '/etc/passwd', '/shell.php',
  '/cmd.php', '/xmlrpc.php', '/wp-admin/', '/info.php',
  '/phpinfo.php', '/config.php', '/backup.sql',
  '/api/users', '/v1/admin', '/.git/config',
];
const DECEPTION_UAS = [
  'Mozilla/5.0 (compatible; Googlebot/2.1)',
  'python-requests/2.28.0',
  'curl/7.68.0',
  'Nikto/2.1.6',
  'sqlmap/1.7.5#stable (https://sqlmap.org)',
  'masscan/1.3 (https://github.com/robertdavidgraham/masscan)',
  'zgrab/0.x',
  'Go-http-client/1.1',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
];
const DECEPTION_IPS = [
  '185.220.101.47', '45.155.205.233', '194.165.16.78',
  '103.75.190.12',  '91.108.56.180',  '5.188.206.14',
  '222.186.42.117', '114.119.130.5',  '36.110.228.254',
  '162.247.74.200', '78.128.113.233', '198.96.155.3',
  '109.70.100.18',  '23.129.64.131',  '185.107.56.43',
  '1.34.55.120',    '211.75.100.5',   '59.125.238.9',
];

function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d;
}

function randomTimestamp(baseDate) {
  const t = new Date(baseDate);
  t.setHours(randInt(3, 23));
  t.setMinutes(randInt(0, 59));
  t.setSeconds(randInt(0, 59));
  return t.toISOString().replace('T', ' ').slice(0, 19);
}

export function seedDemoDatabase() {
  const database = db.getDb();

  const bhCount = database.prepare('SELECT COUNT(*) as c FROM blackhole_log').get();
  const decCount = database.prepare('SELECT COUNT(*) as c FROM deception_log').get();

  if (bhCount.c > 0 && decCount.c > 0) {
    console.log('[DEMO] 資料庫已有資料，跳過 seed');
    return;
  }

  console.log('[DEMO] 正在植入示範資料...');

  const bhInsert = database.prepare(
    'INSERT INTO blackhole_log (cidr, reason, source, created_at) VALUES (?, ?, ?, ?)'
  );
  const seedTx = database.transaction(() => {
    let ipIdx = 0;
    for (let day = 13; day >= 0; day--) {
      const base = daysAgo(day);
      const count = randInt(1, 3);
      for (let i = 0; i < count && ipIdx < SEED_BLACKHOLE_IPS.length; i++, ipIdx++) {
        const { ip, reason, source } = SEED_BLACKHOLE_IPS[ipIdx];
        const cidr = `${ip}/32`;
        const ts = randomTimestamp(base);
        if (day < 5 && Math.random() < 0.3) {
          const revokedTs = new Date(new Date(ts).getTime() + randInt(3600, 86400) * 1000)
            .toISOString().replace('T', ' ').slice(0, 19);
          database.prepare(
            'INSERT INTO blackhole_log (cidr, reason, source, created_at, revoked_at, revoked_by) VALUES (?, ?, ?, ?, ?, ?)'
          ).run(cidr, reason, source, ts, revokedTs, 'admin');
        } else {
          bhInsert.run(cidr, reason, source, ts);
        }
      }
    }

    const decInsert = database.prepare(
      'INSERT INTO deception_log (method, path, query, ip, user_agent, body_preview, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    );
    for (let day = 13; day >= 0; day--) {
      const base = daysAgo(day);
      const count = randInt(10, 50);
      for (let i = 0; i < count; i++) {
        const path = pick(DECEPTION_PATHS);
        const ip = pick(DECEPTION_IPS);
        const ua = pick(DECEPTION_UAS);
        const method = Math.random() < 0.7 ? 'GET' : 'POST';
        const query = path.includes('wp-login') ? 'redirect_to=%2Fwp-admin%2F' : '';
        const body = method === 'POST' ? `username=admin&password=${randInt(1000, 9999)}` : '';
        decInsert.run(method, path, query, ip, ua, body, randomTimestamp(base));
      }
    }

    const credInsert = database.prepare(
      'INSERT INTO credential_log (ip, user_agent, username, password, path, attempt_num, created_at) VALUES (?,?,?,?,?,?,?)'
    );
    const credPaths = ['/login', '/wp-login.php', '/phpmyadmin/'];
    const usernames = ['admin', 'root', 'administrator', 'edu-admin', 'T00312', 'S110001'];
    const passwords = ['123456', 'admin', 'password', 'letmein', 'qwerty', 'Gh$hs_2024'];
    for (let day = 13; day >= 0; day--) {
      const base = daysAgo(day);
      const count = randInt(3, 12);
      for (let i = 0; i < count; i++) {
        credInsert.run(
          pick(DECEPTION_IPS),
          pick(DECEPTION_UAS),
          pick(usernames),
          pick(passwords),
          pick(credPaths),
          randInt(1, 5),
          randomTimestamp(base)
        );
      }
    }
  });

  seedTx();
  console.log('[DEMO] 示範資料植入完成');
}
