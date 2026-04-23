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

  const highTraffic = flowSummary
    .filter((f) => f.packets > 500)
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

const NORMAL_SRCS = [
  '140.112.8.1',   '140.112.8.2',   '140.112.8.3',
  '192.168.10.5',  '192.168.10.12', '192.168.10.23',
  '10.87.87.10',   '10.87.87.11',   '10.87.87.20',
  '172.16.5.100',  '172.16.5.101',
];
const ATTACK_SRCS = [
  '185.220.101.47', '45.155.205.233', '194.165.16.78',
  '103.75.190.12',  '91.108.56.180',  '5.188.206.14',
];
const DSTS = [
  '10.87.87.2', '10.87.87.3', '10.87.87.4',
  '140.112.8.100', '140.112.8.101',
];
const PROTOCOLS = ['tcp', 'udp', 'icmp'];
const COMMON_PORTS = [80, 443, 22, 8080, 53, 25, 3306, 5432];

function randInt(min, max) {
  return min + Math.floor(Math.random() * (max - min + 1));
}
function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function generateFlowBatch(isAttackWindow) {
  const flows = [];
  for (let i = 0; i < randInt(3, 8); i++) {
    flows.push({
      src: pick(NORMAL_SRCS),
      dst: pick(DSTS),
      sport: randInt(1024, 65535),
      dport: pick(COMMON_PORTS),
      protocol: pick(PROTOCOLS),
      packets: randInt(1, 50),
      bytes: randInt(100, 8000),
    });
  }
  if (isAttackWindow) {
    const attacker = pick(ATTACK_SRCS);
    for (let i = 0; i < randInt(5, 15); i++) {
      flows.push({
        src: attacker,
        dst: '10.87.87.2',
        sport: randInt(1024, 65535),
        dport: pick([80, 443, 53]),
        protocol: pick(['tcp', 'udp']),
        packets: randInt(500, 5000),
        bytes: randInt(50000, 500000),
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
