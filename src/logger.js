const LOG_LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const levelName = process.env.LOG_LEVEL || 'info';
const currentLevel = LOG_LEVELS[levelName] ?? LOG_LEVELS.info;

function substitute(formatStr, rest) {
  if (typeof formatStr !== 'string' || !rest.length) return formatStr;
  let i = 0;
  return formatStr.replace(/%([sdioj%])/g, (_, spec) => {
    if (spec === '%') return '%';
    const arg = rest[i++];
    if (arg === undefined) return String(arg);
    if (spec === 's') return String(arg);
    if (spec === 'd' || spec === 'i') return Number(arg);
    if (spec === 'o' || spec === 'j') return typeof arg === 'object' ? JSON.stringify(arg) : String(arg);
    return String(arg);
  });
}

function format(level, ...args) {
  const ts = new Date().toISOString();
  const first = args[0];
  const msg = typeof first === 'string' && /%[sdioj%]/.test(first)
    ? substitute(first, args.slice(1))
    : args.map((a) => (typeof a === 'object' ? JSON.stringify(a) : String(a))).join(' ');
  return `${ts} [${level.toUpperCase()}] ${msg}`;
}

export function log(level, ...args) {
  if ((LOG_LEVELS[level] ?? 0) > currentLevel) return;
  const line = format(level, ...args);
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

export const logger = {
  info: (...args) => log('info', ...args),
  warn: (...args) => log('warn', ...args),
  error: (...args) => log('error', ...args),
  debug: (...args) => log('debug', ...args),
};

export default logger;
