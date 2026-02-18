export function flagFromCountryCode(code) {
  if (!code || code.length !== 2) return '';
  const a = 0x1f1e6;
  const c1 = a + (code.charCodeAt(0) - 65);
  const c2 = a + (code.charCodeAt(1) - 65);
  return String.fromCodePoint(c1, c2);
}

const COUNTRY_NAMES = {
  TW: '台灣', CN: '中國', US: '美國', JP: '日本', KR: '南韓', HK: '香港',
  RU: '俄羅斯', DE: '德國', GB: '英國', FR: '法國', NL: '荷蘭', IN: '印度',
  BR: '巴西', SG: '新加坡', MY: '馬來西亞', TH: '泰國', VN: '越南',
  ID: '印尼', PH: '菲律賓', AU: '澳洲', CA: '加拿大', UA: '烏克蘭',
  PL: '波蘭', TR: '土耳其', IR: '伊朗', SA: '沙烏地', IL: '以色列',
  XX: '未知', '': '未知',
};
export function countryName(code) {
  return COUNTRY_NAMES[code] || code || '未知';
}

export { COUNTRY_NAMES };
