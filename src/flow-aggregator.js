const DEFAULT_WINDOW_MS = 120_000;
const RECENT_FLOWS_MAX = 500;

export class FlowAggregator {
  constructor(windowMs = DEFAULT_WINDOW_MS) {
    this.windowMs = windowMs;
    this.flows = new Map();
    this.recentFlows = [];
    this.started = Date.now();
  }

  key(src, dst, sport, dport, protocol) {
    return `${src}|${dst}|${sport ?? ''}|${dport ?? ''}|${protocol}`;
  }

  add(r) {
    const src = normalizeIp(r.src);
    const dst = normalizeIp(r.dst);
    if (!src || !dst) return;
    const sport = r.sport ?? 0;
    const dport = r.dport ?? 0;
    const protocol = String(r.protocol || 'unknown').toLowerCase();
    const packets = Math.max(1, r.packets ?? 1);
    const bytes = Math.max(0, r.bytes ?? 0);
    const now = Date.now();
    const k = this.key(src, dst, sport, dport, protocol);
    const existing = this.flows.get(k);
    if (existing) {
      existing.packets += packets;
      existing.bytes += bytes;
      existing.last = now;
    } else {
      this.flows.set(k, {
        src,
        dst,
        sport,
        dport,
        protocol,
        packets,
        bytes,
        first: now,
        last: now,
      });
    }
    this.recentFlows.push({
      src,
      dst,
      sport,
      dport,
      protocol,
      packets,
      bytes,
      direction: classifyDirection(src, dst),
      at: now,
    });
    if (this.recentFlows.length > RECENT_FLOWS_MAX) this.recentFlows.shift();
  }

  getRecentFlows() {
    return [...this.recentFlows].reverse();
  }

  getSummaryAndMaybeClear(clear = true) {
    const cutoff = Date.now() - this.windowMs;
    const list = [];
    const toDelete = [];
    for (const [k, v] of this.flows) {
      if (v.last >= cutoff) {
        list.push({
          src: v.src,
          dst: v.dst,
          sport: v.sport,
          dport: v.dport,
          protocol: v.protocol,
          packets: v.packets,
          bytes: v.bytes,
        });
      }
      if (clear && v.last >= cutoff) toDelete.push(k);
    }
    if (clear) {
      for (const k of toDelete) this.flows.delete(k);
    }
    return list;
  }
}

function normalizeIp(v) {
  if (!v) return '';
  const s = String(v).trim();
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s)) return s;
  if (s.includes(':')) return s;
  return '';
}

// 判斷是否為內網 IP（10.87.87.0/24 校園網段 + 標準私有範圍）
function isPrivateIp(ip) {
  if (!ip) return false;
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  const [a, b, c] = parts;
  return (
    (a === 10 && b === 87 && c === 87) || // 校園主網段
    (a === 10) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

export function classifyDirection(src, dst) {
  const srcPriv = isPrivateIp(src);
  const dstPriv = isPrivateIp(dst);
  if (srcPriv && !dstPriv) return 'outbound';
  if (!srcPriv && dstPriv) return 'inbound';
  if (srcPriv && dstPriv) return 'internal';
  return 'external';
}

export default FlowAggregator;
