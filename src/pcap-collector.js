import { config } from './config.js';

let pcap = null;
try {
  pcap = (await import('pcap')).default;
} catch (_) {
}

export async function startPcapCollector(aggregator) {
  if (!config.pcap.enabled || !pcap) return null;
  const iface = config.pcap.interface;
  try {
    const session = pcap.createSession(iface, { filter: 'ip' });
    session.on('packet', (raw) => {
      try {
        const pkt = pcap.decode.packet(raw);
        const ip = pkt?.payload?.payload;
        if (!ip?.saddr || !ip?.daddr) return;
        const src = formatIp(ip.saddr);
        const dst = formatIp(ip.daddr);
        if (!src || !dst) return;
        const sport = ip.sport ?? 0;
        const dport = ip.dport ?? 0;
        const protocol = ip.protocol === 6 ? 'tcp' : ip.protocol === 17 ? 'udp' : String(ip.protocol ?? '');
        aggregator.add({ src, dst, sport, dport, protocol, packets: 1, bytes: raw.length });
      } catch (_) {}
    });
    console.log(`[pcap] 監聽介面 ${iface}`);
    return {
      close: () => {
        try {
          session.close?.();
        } catch (_) {}
      },
    };
  } catch (e) {
    console.warn('[pcap] 無法啟動:', e.message);
    return null;
  }
}

function formatIp(addr) {
  if (typeof addr === 'string') return addr;
  if (Array.isArray(addr)) return addr.join('.');
  return String(addr);
}
