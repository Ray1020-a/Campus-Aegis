import { GoogleGenAI } from "@google/genai";
import { config } from "./config.js";

const { apiKey, model } = config.gemini;

const systemAndUser = (
  flowJson,
) => `你是一個網路安全分析師。你會收到一段時間內的「流量彙總」列表，每筆包含：src（來源IP）、dst（目的IP）、sport/dport（port）、protocol、packets、bytes。
請根據行為判斷「疑似惡意」的來源 IP 或目的 IP（例如：DDoS、掃描、異常大量連線、明顯異常的封包/位元組比例）。
只輸出要黑洞的 IP 清單，不要解釋。格式嚴格為 JSON 陣列字串，例如：["1.2.3.4","5.6.7.8"]，若沒有則輸出 []。
只輸出該 JSON 陣列，不要其他文字。
請注意，不要封鎖「10.87.87.2」
請分析以下流量彙總並輸出要黑洞的 IP 的 JSON 陣列：
${flowJson}`;

const MAX_RETRIES = 2;
const DEFAULT_RETRY_SEC = 5;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function isQuotaError(err) {
  const msg = err?.message ?? String(err);
  const code = err?.code ?? err?.status;
  return (
    code === 429 ||
    msg.includes("429") ||
    msg.includes("RESOURCE_EXHAUSTED") ||
    msg.includes("quota") ||
    msg.includes("rate")
  );
}

function parseRetryDelaySeconds(err) {
  try {
    const msg = err?.message ?? String(err);
    const m =
      msg.match(/retry in (\d+(?:\.\d+)?)\s*s/i) ||
      msg.match(/"retryDelay":"(\d+)s"/);
    if (m) return Math.min(Number(m[1]) + 0.5, 60);
    let details = err?.details ?? err?.error?.details;
    if (!details && typeof msg === "string" && msg.includes("RetryInfo")) {
      try {
        const parsed = JSON.parse(msg);
        details = parsed?.error?.details ?? parsed?.details;
      } catch (_) {}
    }
    if (Array.isArray(details)) {
      const retryInfo = details.find(
        (d) => d && (d["@type"]?.includes("RetryInfo") || d.retryDelay),
      );
      if (retryInfo?.retryDelay) {
        const sec =
          Number(String(retryInfo.retryDelay).replace(/s$/, "")) ||
          DEFAULT_RETRY_SEC;
        return Math.min(sec + 0.5, 60);
      }
    }
  } catch (_) {}
  return DEFAULT_RETRY_SEC;
}

/**
 * @param {Array<{ src: string, dst: string, sport: number, dport: number, protocol: string, packets: number, bytes: number }>} flowSummary
 * @returns {Promise<string[]>}
 */
export async function analyzeWithGemini(flowSummary) {
  if (!apiKey) {
    console.warn("[Gemini] 未設定 GEMINI_API_KEY，跳過分析");
    return [];
  }
  if (!flowSummary.length) return [];

  const flowJson = JSON.stringify(flowSummary.slice(0, 500), null, 0);
  const ai = new GoogleGenAI({ apiKey });

  let lastErr;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      const resp = await ai.models.generateContent({
        model,
        contents: systemAndUser(flowJson),
      });
      const raw = resp?.text ?? "";
      const trimmed = raw
        .replace(/^[\s`]*|[\s`]*$/g, "")
        .replace(/^.*?(\[.*\]).*$/s, "$1");
      try {
        const arr = JSON.parse(trimmed);
        if (!Array.isArray(arr)) return [];
        return arr
          .filter((x) => typeof x === "string" && /^[\d.]+$/.test(x))
          .map((x) => `${x}/32`);
      } catch (_) {
        return [];
      }
    } catch (err) {
      lastErr = err;
      if (attempt < MAX_RETRIES && isQuotaError(err)) {
        const sec = parseRetryDelaySeconds(err);
        console.warn(
          `[Gemini] 配額/頻率限制 (429)，${sec} 秒後重試 (${attempt + 1}/${MAX_RETRIES})…`,
        );
        await sleep(sec * 1000);
        continue;
      }
      throw err;
    }
  }
  throw lastErr;
}
