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

export default FlowAggregator;
