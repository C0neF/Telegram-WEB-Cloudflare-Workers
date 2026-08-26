import assert from 'node:assert/strict';

const url = process.argv[2] ?? 'ws://127.0.0.1:8791/probe/ws';
const socket = new WebSocket(url);
socket.binaryType = 'arraybuffer';

const messages = [];
const done = new Promise((resolve, reject) => {
  const timeout = setTimeout(() => reject(new Error('WebSocket echo timed out')), 5000);

  socket.addEventListener('open', () => {
    socket.send('validation-text');
    socket.send(Uint8Array.from([1, 2, 3, 4]));
  });
  socket.addEventListener('message', (event) => {
    messages.push(event.data);
    if (messages.length === 2) {
      clearTimeout(timeout);
      resolve();
    }
  });
  socket.addEventListener('error', () => reject(new Error('WebSocket echo failed')));
});

await done;
assert.equal(messages[0], 'validation-text');
assert.deepEqual(Buffer.from(messages[1]), Buffer.from([1, 2, 3, 4]));
socket.close(1000, 'validation complete');
console.log(JSON.stringify({ ok: true, url, textEcho: true, binaryEcho: true }));
