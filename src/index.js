import { config, validateConfig } from './config.js';
import { logger } from './logger.js';
import { state, setLastDefense } from './state.js';
import { FlowAggregator } from './flow-aggregator.js';
import { startNetFlowCollector } from './netflow-collector.js';
import { startPcapCollector } from './pcap-collector.js';
import { analyzeWithGemini } from './gemini-analyzer.js';
import { addBlackhole } from './vyos-client.js';
import * as db from './db.js';
import { createApp } from './admin-server.js';
import { deceptionApp } from './deception-server.js';

const intervalMs = (config.gemini.intervalSeconds || 120) * 1000;
const aggregator = new FlowAggregator(intervalMs);

let netflowHandle = null;
let pcapHandle = null;
let adminServer = null;
let deceptionServer = null;

async function runDefenseCycle() {
  const summary = aggregator.getSummaryAndMaybeClear(true);
  if (!summary.length) {
    logger.debug('[防禦] 本週期無流量摘要，跳過');
    return;
  }
  logger.info('[防禦] 本週期流量筆數: %d', summary.length);
  let toBlock = [];
  try {
    toBlock = await analyzeWithGemini(summary);
  } catch (e) {
    logger.error('[Gemini] 分析失敗: %s', e.message);
    setLastDefense({ flowCount: summary.length, suggestedCount: 0, blockedCount: 0, error: e.message });
    return;
  }
  if (!toBlock.length) {
    logger.info('[防禦] Gemini 未建議黑洞任何 IP');
    setLastDefense({ flowCount: summary.length, suggestedCount: 0, blockedCount: 0 });
    return;
  }
  const activeSet = db.getActiveBlackholeCidrs();
  const toBlockNew = toBlock.filter((cidr) => {
    const normalized = (cidr || '').trim().includes('/') ? (cidr || '').trim() : `${(cidr || '').trim()}/32`;
    return !activeSet.has(normalized);
  });
  const skipped = toBlock.length - toBlockNew.length;
  if (skipped > 0) {
    logger.info('[防禦] 略過已存在黑洞的 IP: %d 筆', skipped);
  }
  if (!toBlockNew.length) {
    logger.info('[防禦] 建議的 IP 皆已在黑洞中，無需重複下達');
    setLastDefense({ flowCount: summary.length, suggestedCount: toBlock.length, blockedCount: 0 });
    return;
  }
  logger.info('[防禦] 建議黑洞: %o', toBlockNew);
  let blocked = 0;
  for (const cidr of toBlockNew) {
    try {
      await addBlackhole(cidr);
      db.logBlackhole(cidr, 'gemini 判定', 'gemini');
      blocked++;
      logger.info('[VyOS] 已黑洞: %s', cidr);
    } catch (e) {
      logger.error('[VyOS] 黑洞失敗 %s: %s', cidr, e.message);
    }
  }
  setLastDefense({ flowCount: summary.length, suggestedCount: toBlockNew.length, blockedCount: blocked });
}

function shutdown(signal) {
  logger.info('收到 %s，正在優雅關閉…', signal);
  if (netflowHandle?.close) {
    try { netflowHandle.close(); } catch (_) {}
    netflowHandle = null;
  }
  if (pcapHandle?.close) {
    try { pcapHandle.close(); } catch (_) {}
    pcapHandle = null;
  }
  const close = (s) => {
    if (s && typeof s.close === 'function') {
      s.close(() => logger.info('服務已關閉'));
    }
  };
  close(adminServer);
  close(deceptionServer);
  setTimeout(() => process.exit(0), 3000);
}

async function main() {
  try {
    validateConfig();
  } catch (e) {
    logger.error(e.message);
    process.exit(1);
  }

  logger.info('Campus Aegis 校園神盾 啟動');
  logger.info('防禦週期: %d 秒', config.gemini.intervalSeconds);

  if (config.netflow.enabled) {
    try {
      netflowHandle = await startNetFlowCollector(aggregator);
    } catch (e) {
      logger.error('[NetFlow] 啟動失敗: %s', e.message);
    }
  }

  pcapHandle = await startPcapCollector(aggregator);

  const adminApp = createApp(aggregator);
  adminServer = adminApp.listen(config.admin.port, config.admin.bindHost, () => {
    logger.info('[admin] 管理員面板 http://%s:%d', config.admin.bindHost, config.admin.port);
  });
  deceptionServer = deceptionApp.listen(config.deception.port, config.deception.bindHost, () => {
    logger.info('[誘騙服務] 假系統監聽 http://%s:%d（供 Nginx proxy 導向）', config.deception.bindHost, config.deception.port);
  });

  state.servers.push(adminServer, deceptionServer);

  setInterval(runDefenseCycle, intervalMs);
  setTimeout(runDefenseCycle, Math.min(intervalMs, 60_000));

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((e) => {
  logger.error(e);
  process.exit(1);
});
