const startTime = Date.now();

export const state = {
  lastDefenseAt: null,
  lastDefenseResult: null,
  netflowReceived: false,
  servers: [],
};

export function getUptimeSeconds() {
  return Math.floor((Date.now() - startTime) / 1000);
}

export function setLastDefense(result) {
  state.lastDefenseAt = new Date().toISOString();
  state.lastDefenseResult = result;
}

export function setNetflowReceived() {
  state.netflowReceived = true;
}
