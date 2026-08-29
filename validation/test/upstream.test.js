import assert from 'node:assert/strict';
import test from 'node:test';

import { PINNED_UPSTREAM, readPinnedSource } from '../src/upstream.js';

test('validation is anchored to the pinned server protocol and Desktop v7.1.2 commits', async () => {
  assert.deepEqual(PINNED_UPSTREAM, {
    server: '52a5feb7fac38f68da5afef9cedd9b3bfc8473ca',
    desktop: '3772337dd3e435b6269297f9db8f65959f8abe89',
  });

  const protocol = await readPinnedSource('server', 'PROTOCOL.md');
  assert.match(protocol, /type:u8 \| stream_id:u24 \| payload_length:u32 \| payload/);
  assert.match(protocol, /`0x10` \| `HELLO` \| client → relay \| zero \| byte `01`/);
  assert.match(protocol, /`0x11` \| `WELCOME` \| relay → client \| zero \| empty/);
  assert.match(protocol, /Sec-WebSocket-Protocol: tproxy-v1\.<session-token>/);

  const frameHeader = await readPinnedSource(
    'desktop',
    'Telegram/SourceFiles/mtproto/web_proxy/web_proxy_frame.h',
  );
  assert.match(frameHeader, /kMaxFramePayload = 1024 \* 1024/);
  assert.match(frameHeader, /kMaxBatchFrames = 4096/);
  assert.match(frameHeader, /kInitialStreamWindow = 4 \* 1024 \* 1024/);
  assert.match(frameHeader, /AuthChallenge = 0x12/);
  assert.match(frameHeader, /AuthResponse = 0x13/);
});

test('pinned Desktop source maps 16-byte secret to abridged and negative DC to media', async () => {
  const connection = await readPinnedSource(
    'desktop',
    'Telegram/SourceFiles/mtproto/connection_tcp.cpp',
  );
  assert.match(connection, /else if \(secret\.size\(\) == 16\)/);
  assert.match(connection, /return 0xEFEFEFEFU/);

  const session = await readPinnedSource(
    'desktop',
    'Telegram/SourceFiles/mtproto/session_private.cpp',
  );
  assert.match(session, /\? -testedDcId/);
});
