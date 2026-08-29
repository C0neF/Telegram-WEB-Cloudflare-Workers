export const TELEGRAM_HOSTS = Object.freeze([
  'pluto.web.telegram.org',
  'venus.web.telegram.org',
  'aurora.web.telegram.org',
  'vesta.web.telegram.org',
  'flora.web.telegram.org',
]);

export function telegramHostForDc(dcId) {
  const baseDcId = Math.abs(dcId);
  if (!Number.isInteger(dcId) || dcId === 0 || baseDcId > TELEGRAM_HOSTS.length) {
    throw new RangeError(`Unsupported Telegram DC id: ${dcId}`);
  }
  return TELEGRAM_HOSTS[baseDcId - 1];
}
