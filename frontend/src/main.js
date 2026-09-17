import './style.css';
import './app.css';

import {Connect, Disconnect, Status} from '../wailsjs/go/main/App';

document.querySelector('#app').innerHTML = `
  <main class="shell">
    <header class="topbar"><div class="brand"><span class="brand-mark">S</span><span>SSH Tunnel</span></div><span class="phase">PHASE 01 / SOCKS5</span></header>
    <section class="workspace">
      <div class="intro"><p class="eyebrow">Encrypted transport</p><h1>Route your browser<br><em>through SSH.</em></h1><p class="lede">Connect to a VPS and expose a local SOCKS5 proxy. System-wide routing is intentionally not enabled in this first phase.</p><div class="signal"><span class="signal-dot"></span><span id="connection-label">Ready to connect</span></div></div>
      <form class="panel" id="connection-form">
        <div class="panel-heading"><div><p class="eyebrow">VPS profile</p><h2>Connection details</h2></div><span class="lock">LOCKED</span></div>
        <div class="mode-tabs"><button type="button" class="mode active" data-mode="proxy"><strong>Proxy</strong><small>System proxy</small></button><button type="button" class="mode" data-mode="full"><strong>Full tunnel</strong><small>All system traffic</small></button></div>
        <label>DNS resolver<select id="dns"><option value="1.1.1.1,1.0.0.1">Cloudflare — 1.1.1.1</option><option value="8.8.8.8,8.8.4.4">Google — 8.8.8.8</option><option value="9.9.9.9,149.112.112.112">Quad9 — 9.9.9.9</option><option value="94.140.14.14,94.140.15.15">AdGuard — 94.140.14.14</option><option value="208.67.222.222,208.67.220.220">OpenDNS — 208.67.222.222</option></select></label>
        <label class="checkbox"><input id="use-ipv6" type="checkbox"><span>Use IPv6 in Full Tunnel</span></label>
        <label>Host or IP<input id="host" type="text" placeholder="vps.example.com" autocomplete="off" required></label>
        <div class="split"><label>SSH port<input id="port" type="number" value="22" min="1" max="65535"></label><label>Local SOCKS5 port<input id="proxy-port" type="number" value="1080" min="1" max="65535"></label></div>
        <label>Username<input id="username" type="text" placeholder="root" autocomplete="username" required></label>
        <div class="method-tabs"><button type="button" class="method active" data-method="password">Password</button><button type="button" class="method" data-method="key">Private key</button></div>
        <label id="password-field">Password<input id="password" type="password" placeholder="Enter SSH password" autocomplete="current-password"></label>
        <label id="key-field" class="hidden">Private key<textarea id="private-key" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></label>
        <button class="connect" id="connect-button" type="submit"><span class="button-dot"></span><span id="button-label">Connect tunnel</span></button>
        <p class="message" id="message">Credentials stay in memory for this session.</p>
      </form>
    </section>
    <footer class="footer"><span>LOCAL PROXY</span><strong id="proxy-address">127.0.0.1:1080</strong><span class="footer-note">SSH host key verification is disabled in this MVP.</span></footer>
  </main>`;

const form = document.querySelector('#connection-form');
const connectButton = document.querySelector('#connect-button');
const buttonLabel = document.querySelector('#button-label');
const message = document.querySelector('#message');
const connectionLabel = document.querySelector('#connection-label');
const proxyAddress = document.querySelector('#proxy-address');
const passwordField = document.querySelector('#password-field');
const keyField = document.querySelector('#key-field');
let method = 'password';
let mode = 'proxy';
let connected = false;

document.querySelectorAll('.mode').forEach((button) => button.addEventListener('click', () => {
  mode = button.dataset.mode;
  document.querySelectorAll('.mode').forEach((item) => item.classList.toggle('active', item === button));
  message.textContent = mode === 'full' ? 'Full Tunnel uses Wintun and requires Administrator access.' : 'Windows proxy settings will be restored on disconnect.';
}));

document.querySelectorAll('.method').forEach((button) => button.addEventListener('click', () => {
  method = button.dataset.method;
  document.querySelectorAll('.method').forEach((item) => item.classList.toggle('active', item === button));
  passwordField.classList.toggle('hidden', method !== 'password');
  keyField.classList.toggle('hidden', method !== 'key');
}));

function showStatus(status) {
  connected = status.state === 'connected';
  connectionLabel.textContent = status.message || status.state;
  message.textContent = status.message || '';
  message.className = `message ${status.state}`;
  proxyAddress.textContent = status.proxy || `127.0.0.1:${document.querySelector('#proxy-port').value}`;
  buttonLabel.textContent = connected ? 'Disconnect tunnel' : 'Connect tunnel';
  connectButton.classList.toggle('disconnect', connected);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  connectButton.disabled = true;
  try {
    const status = connected ? await Disconnect() : await Connect({
      host: document.querySelector('#host').value.trim(), port: Number(document.querySelector('#port').value),
      username: document.querySelector('#username').value.trim(), password: method === 'password' ? document.querySelector('#password').value : '',
      privateKey: method === 'key' ? document.querySelector('#private-key').value : '', proxyPort: Number(document.querySelector('#proxy-port').value), mode,
      dns: document.querySelector('#dns').value.split(','),
      useIPv6: document.querySelector('#use-ipv6').checked,
    });
    showStatus(status);
  } catch (error) { showStatus({state: 'error', message: error.toString()}); }
  finally { connectButton.disabled = false; }
});

Status().then(showStatus).catch(() => {});