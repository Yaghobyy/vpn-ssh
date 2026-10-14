import './style.css';
import './app.css';

import {Connect, Disconnect, LoadSettings, SaveSettings, Status} from '../wailsjs/go/main/App';

document.querySelector('#app').innerHTML = `
  <main class="shell">
    <header class="topbar"><div class="brand"><span class="brand-mark">S</span><span>SSH Tunnel</span></div><span class="phase">PHASE 01 / SOCKS5</span></header>
    <section class="workspace">
      <form class="panel" id="connection-form">
        <div class="panel-heading"><div><p class="eyebrow">VPS profile</p></div><span class="lock">LOCKED</span></div>
        <div class="mode-tabs"><button type="button" class="mode active" data-mode="proxy"><strong>Proxy</strong><small>System proxy</small></button><button type="button" class="mode" data-mode="full"><strong>Full tunnel</strong><small>All system traffic</small></button></div>
        <label>DNS resolver<select id="dns"><option value="1.1.1.1,1.0.0.1">Cloudflare — 1.1.1.1</option><option value="8.8.8.8,8.8.4.4">Google — 8.8.8.8</option><option value="9.9.9.9,149.112.112.112">Quad9 — 9.9.9.9</option><option value="94.140.14.14,94.140.15.15">AdGuard — 94.140.14.14</option><option value="208.67.222.222,208.67.220.220">OpenDNS — 208.67.222.222</option></select></label>
        <label class="checkbox"><input id="use-ipv6" type="checkbox"><span>Use IPv6 in Full Tunnel</span></label>
        <label>Host or IP<input id="host" type="text" placeholder="vps.example.com" autocomplete="off" required></label>
        <div class="split"><label>SSH port<input id="port" type="number" value="22" min="1" max="65535"></label><label>Local SOCKS5 port<input id="proxy-port" type="number" value="1080" min="1" max="65535"></label></div>
        <label>Username<input id="username" type="text" placeholder="root" autocomplete="username" required></label>
        <div class="method-tabs"><button type="button" class="method active" data-method="password">Password</button><button type="button" class="method" data-method="key">Private key</button></div>
        <label id="password-field">Password<input id="password" type="password" placeholder="Enter SSH password" autocomplete="current-password"></label>
        <label id="key-field" class="hidden">Private key<textarea id="private-key" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></label>
        <p class="message" id="message">Settings are saved locally; credentials are protected by Windows.</p>
      </form>
      <div class="connect-stage">
        <button class="connect" id="connect-button" type="submit" form="connection-form" aria-label="Connect tunnel">
          <span class="power-icon" aria-hidden="true">⏻</span>
          <span id="button-label">Connect</span>
        </button>
        <div class="traffic-metrics" aria-live="polite">
          <div class="traffic-metric"><span class="traffic-label">DOWNLOAD</span><strong id="download-speed">0 B/s</strong></div>
          <div class="traffic-metric"><span class="traffic-label">UPLOAD</span><strong id="upload-speed">0 B/s</strong></div>
        </div>
        <div class="traffic-totals" aria-live="polite">
          <div class="traffic-total"><span class="traffic-label">TOTAL DOWNLOADED</span><strong id="download-total">0 B</strong></div>
          <div class="traffic-total"><span class="traffic-label">TOTAL UPLOADED</span><strong id="upload-total">0 B</strong></div>
        </div>
        <div class="connection-state"><span class="signal-dot"></span><span id="connection-label">Ready to connect</span></div>
        <p class="connect-hint">SSH TUNNEL</p>
      </div>
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
let isBusy = false;
let settingsSaveTimer;
let lastStatus;
let previousTrafficSample;

function setMode(value) {
  mode = value === 'full' ? 'full' : 'proxy';
  document.querySelectorAll('.mode').forEach((button) => button.classList.toggle('active', button.dataset.mode === mode));
}

function setMethod(value) {
  method = value === 'key' ? 'key' : 'password';
  document.querySelectorAll('.method').forEach((button) => button.classList.toggle('active', button.dataset.method === method));
  passwordField.classList.toggle('hidden', method !== 'password');
  keyField.classList.toggle('hidden', method !== 'key');
}

function collectSettings() {
  return {
    host: document.querySelector('#host').value.trim(),
    port: Number(document.querySelector('#port').value),
    username: document.querySelector('#username').value.trim(),
    password: document.querySelector('#password').value,
    privateKey: document.querySelector('#private-key').value,
    proxyPort: Number(document.querySelector('#proxy-port').value),
    mode,
    dns: document.querySelector('#dns').value.split(','),
    useIPv6: document.querySelector('#use-ipv6').checked,
    authMethod: method,
  };
}

function queueSettingsSave() {
  window.clearTimeout(settingsSaveTimer);
  settingsSaveTimer = window.setTimeout(() => {
    SaveSettings(collectSettings()).catch((error) => {
      message.textContent = `Could not save settings: ${error}`;
      message.className = 'message error';
    });
  }, 250);
}

function applySettings(settings) {
  document.querySelector('#host').value = settings.host || '';
  document.querySelector('#port').value = settings.port || 22;
  document.querySelector('#username').value = settings.username || '';
  document.querySelector('#password').value = settings.password || '';
  document.querySelector('#private-key').value = settings.privateKey || '';
  document.querySelector('#proxy-port').value = settings.proxyPort || 1080;
  document.querySelector('#dns').value = (settings.dns || ['1.1.1.1', '1.0.0.1']).join(',');
  document.querySelector('#use-ipv6').checked = Boolean(settings.useIPv6);
  setMode(settings.mode);
  setMethod(settings.authMethod);
}

document.querySelectorAll('.mode').forEach((button) => button.addEventListener('click', () => {
  setMode(button.dataset.mode);
  message.textContent = mode === 'full' ? 'Full Tunnel uses Wintun and requires Administrator access.' : 'Windows proxy settings will be restored on disconnect.';
  queueSettingsSave();
}));

document.querySelectorAll('.method').forEach((button) => button.addEventListener('click', () => {
  setMethod(button.dataset.method);
  queueSettingsSave();
}));

function handleSettingsChange(event) {
  queueSettingsSave();
}

form.addEventListener('input', handleSettingsChange);
form.addEventListener('change', handleSettingsChange);

function showStatus(status) {
  lastStatus = status;
  connected = status.state === 'connected';
  connectionLabel.textContent = status.message || status.state;
  connectionLabel.parentElement.dataset.state = status.state;
  message.textContent = status.message || '';
  message.className = `message ${status.state}`;
  proxyAddress.textContent = status.proxy || `127.0.0.1:${document.querySelector('#proxy-port').value}`;
  buttonLabel.textContent = connected ? 'Disconnect' : 'Connect';
  connectButton.setAttribute('aria-label', connected ? 'Disconnect tunnel' : 'Connect tunnel');
  connectButton.classList.toggle('disconnect', connected);
  updateTraffic(status);
}

function formatSpeed(bytesPerSecond) {
  if (bytesPerSecond < 1024) return `${Math.round(bytesPerSecond)} B/s`;
  if (bytesPerSecond < 1024 * 1024) return `${(bytesPerSecond / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSecond / (1024 * 1024)).toFixed(1)} MB/s`;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function updateTraffic(status) {
  const downloadElement = document.querySelector('#download-speed');
  const uploadElement = document.querySelector('#upload-speed');
  const downloadTotalElement = document.querySelector('#download-total');
  const uploadTotalElement = document.querySelector('#upload-total');
  downloadTotalElement.textContent = formatBytes(status.downloadBytes || 0);
  uploadTotalElement.textContent = formatBytes(status.uploadBytes || 0);
  if (status.state !== 'connected') {
    previousTrafficSample = undefined;
    downloadElement.textContent = '0 B/s';
    uploadElement.textContent = '0 B/s';
    return;
  }

  const now = performance.now();
  let downloadRate = 0;
  let uploadRate = 0;
  if (previousTrafficSample) {
    const elapsed = (now - previousTrafficSample.time) / 1000;
    if (elapsed > 0) {
      downloadRate = Math.max(0, status.downloadBytes - previousTrafficSample.downloadBytes) / elapsed;
      uploadRate = Math.max(0, status.uploadBytes - previousTrafficSample.uploadBytes) / elapsed;
    }
  }
  previousTrafficSample = {
    time: now,
    downloadBytes: status.downloadBytes,
    uploadBytes: status.uploadBytes,
  };
  downloadElement.textContent = formatSpeed(downloadRate);
  uploadElement.textContent = formatSpeed(uploadRate);
}

function refreshStatus() {
  if (isBusy) return;
  Status().then((status) => {
    if (!lastStatus || status.state !== lastStatus.state || status.address !== lastStatus.address || status.proxy !== lastStatus.proxy || status.message !== lastStatus.message) {
      showStatus(status);
    } else {
      updateTraffic(status);
    }
  }).catch(() => {});
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  isBusy = true;
  connectButton.disabled = true;
  connectButton.classList.add('connecting');
  buttonLabel.textContent = connected ? 'Stopping' : 'Connecting';
  connectionLabel.textContent = connected ? 'Disconnecting tunnel' : 'Establishing secure tunnel';
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
  finally {
    isBusy = false;
    connectButton.disabled = false;
    connectButton.classList.remove('connecting');
  }
});

LoadSettings().then(applySettings).catch((error) => console.error('Could not load settings:', error));
Status().then(showStatus).catch(() => {});
window.setInterval(refreshStatus, 1000);