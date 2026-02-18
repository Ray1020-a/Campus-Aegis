import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const Collector = require('@bettercorp/node-netflowv9');

import { config } from './config.js';
import { setNetflowReceived } from './state.js';

const { port, bindHost } = config.netflow;

export function startNetFlowCollector(aggregator) {
  return new Promise((resolve, reject) => {
    const handler = (flow) => {
      const list = flow?.flows;
      if (!Array.isArray(list) || !list.length) return;
      for (const r of list) {
        const src = r.srcaddr ?? r.ipv4_src_addr ?? r.ipv6_src_addr?.address ?? '';
        const dst = r.dstaddr ?? r.ipv4_dst_addr ?? r.ipv6_dst_addr?.address ?? '';
        const sport = r.l4_src_port ?? r.src_port ?? 0;
        const dport = r.l4_dst_port ?? r.dst_port ?? 0;
        const protocol = r.protocol ?? r.ip_protocol_version ?? 'unknown';
        const packets = r.in_pkts ?? r.packets ?? 1;
        const bytes = r.in_bytes ?? r.bytes ?? 0;
        aggregator.add({
          src: formatIp(src),
          dst: formatIp(dst),
          sport,
          dport,
          protocol: String(protocol),
          packets: Number(packets) || 1,
          bytes: Number(bytes) || 0,
        });
      }
    };
    const opts = { cb: null };
    const collector = new Collector(opts);
    let firstPacketLogged = false;
    let firstFlowLogged = false;
    let totalPackets = 0;
    collector.on('data', (flow) => {
      try {
        totalPackets++;
        const n = Array.isArray(flow?.flows) ? flow.flows.length : 0;
        if (!firstPacketLogged) {
          firstPacketLogged = true;
          console.log(`[NetFlow] 已收到第一個封包，本封包 flow 筆數: ${n}`);
        }
        handler(flow);
        if (!firstFlowLogged && n > 0) {
          firstFlowLogged = true;
          setNetflowReceived();
          console.log('[NetFlow] 已收到第一筆 flow（VyOS 連線正常）');
        }
      } catch (e) {
        console.error('[NetFlow] 處理封包時錯誤:', e.message);
      }
    });
    const countInterval = setInterval(() => {
      if (totalPackets > 0) {
        console.log(`[NetFlow] 目前已累計收到 ${totalPackets} 個封包`);
      }
    }, 30000);
    collector.listen(port, bindHost, (err) => {
      if (err) return reject(err);
      console.log(`[NetFlow] 監聽 ${bindHost}:${port}`);
      resolve({
        close: () => {
          clearInterval(countInterval);
          try {
            collector.close?.();
          } catch (_) {}
        },
      });
    });
  });
}

function formatIp(addr) {
  if (addr == null) return '';
  if (typeof addr === 'number') {
    return ((addr >>> 24) & 0xff) + '.' + ((addr >>> 16) & 0xff) + '.' + ((addr >>> 8) & 0xff) + '.' + (addr & 0xff);
  }
  if (typeof addr === 'string') return addr;
  if (addr && typeof addr === 'object' && addr.address) return addr.address;
  if (Array.isArray(addr)) return addr.join('.');
  return String(addr);
}
