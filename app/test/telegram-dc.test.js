import assert from 'node:assert/strict';
import test from 'node:test';

import {
  TELEGRAM_HOSTS,
  telegramHostForDc,
} from '../../shared/telegram-dc.js';

test('shared Telegram DC map owns host order and signed DC resolution', () => {
  assert.deepEqual(TELEGRAM_HOSTS, [
    'pluto.web.telegram.org',
    'venus.web.telegram.org',
    'aurora.web.telegram.org',
    'vesta.web.telegram.org',
    'flora.web.telegram.org',
  ]);
  assert.equal(telegramHostForDc(1), TELEGRAM_HOSTS[0]);
  assert.equal(telegramHostForDc(-2), TELEGRAM_HOSTS[1]);
  assert.equal(telegramHostForDc(5), TELEGRAM_HOSTS[4]);
  assert.throws(() => telegramHostForDc(0), /dc/i);
  assert.throws(() => telegramHostForDc(6), /dc/i);
});
