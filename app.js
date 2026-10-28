const METRICS_URL = window.OBSERVATORY_METRICS_URL || './metrics.json';
const ACTIVITY_URL = window.OBSERVATORY_ACTIVITY_URL || './activity.json';
const REFRESH_MS = 5 * 60 * 1000;
const ACTIVITY_REFRESH_MS = 15 * 1000;
const number = new Intl.NumberFormat();

const dateLabel = new Intl.DateTimeFormat('en', { month: 'short', day: '2-digit', year: 'numeric', timeZone: 'UTC' });
document.querySelector('#today-date').textContent = `${dateLabel.format(new Date()).toUpperCase()} · UTC`;

const views = {
  overview: [document.querySelector('#overview'), document.querySelector('#feed-notice'), document.querySelector('.live-metrics'), document.querySelector('#live-attacks'), document.querySelector('#timeline'), document.querySelector('#weirdest')],
  rankings: [document.querySelector('#rankings'), document.querySelector('#malware-tools')],
  playback: [document.querySelector('#playback')],
  about: [document.querySelector('#about')]
};
let timelineData = [];
let timelineDays = 7;
let playbackSteps = [];
let playbackIndex = -1;
let playbackTimer = null;
let playbackSignature = '';

function navigateTo(hash, updateHistory = true) {
  const requestedId = hash.replace(/^#/, '');
  const viewId = requestedId === 'top' ? 'overview' : requestedId;
  if (!views[viewId]) return;
  if (updateHistory && window.location.hash !== hash) window.history.pushState(null, '', hash);
  for (const [name, elements] of Object.entries(views)) {
    elements.forEach((element) => element.classList.toggle('route-hidden', name !== viewId));
  }
  document.querySelectorAll('.side-nav .nav-item').forEach((item) => {
    item.classList.toggle('active', item.getAttribute('href') === `#${viewId}`);
  });
  const sectionName = document.querySelector(`.side-nav a[href="#${viewId}"]`)?.textContent.trim();
  if (sectionName) document.querySelector('.breadcrumb strong').textContent = sectionName.toUpperCase();
  const target = document.getElementById(viewId);
  window.scrollTo({ top: 0, behavior: 'smooth' });
  target.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

document.querySelectorAll('a[href^="#"]').forEach((link) => {
  link.addEventListener('click', (event) => {
    const hash = link.getAttribute('href');
    if (!document.getElementById(hash.slice(1))) return;
    event.preventDefault();
    navigateTo(hash);
  });
});

window.addEventListener('load', () => {
  navigateTo(window.location.hash || '#overview', false);
});

window.addEventListener('popstate', () => {
  navigateTo(window.location.hash || '#overview', false);
});

function setStatus(state, message) {
  const status = document.querySelector('#feed-status');
  const notice = document.querySelector('#feed-notice');
  const dot = document.querySelector('#sensor-dot');
  status.dataset.state = state;
  status.lastChild.textContent = ` ${state === 'live' ? 'LIVE' : state === 'stale' ? 'STALE' : 'OFFLINE'}`;
  dot.dataset.state = state;
  notice.dataset.state = state;
  notice.querySelector('p').textContent = message;
}

function metricText(name, value) {
  document.querySelector(`[data-metric="${name}"]`).textContent = value;
}

function renderList(id, items, labelFor, maxCount) {
  const list = document.getElementById(id);
  list.replaceChildren();
  if (!items.length) {
    const empty = document.createElement('li');
    empty.className = 'empty-row';
    empty.textContent = 'No events recorded today';
    list.append(empty);
    return;
  }
  for (const [index, item] of items.slice(0, 8).entries()) {
    const row = document.createElement('li');
    row.className = 'ranking-row';
    const rank = document.createElement('span');
    rank.className = 'rank-number';
    rank.textContent = String(index + 1).padStart(2, '0');
    const label = document.createElement('span');
    label.className = 'rank-label';
    label.textContent = labelFor(item);
    const bar = document.createElement('span');
    bar.className = 'rank-bar';
    const fill = document.createElement('i');
    fill.style.width = `${Math.max(4, Math.min(100, (item.attempts / maxCount) * 100))}%`;
    bar.append(fill);
    const count = document.createElement('strong');
    count.textContent = number.format(item.attempts || 0);
    row.append(rank, label, bar, count);
    list.append(row);
  }
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function renderCommandTools(items) {
  const list = document.querySelector('#tools-list');
  list.replaceChildren();
  if (!items.length) {
    const empty = document.createElement('li');
    empty.className = 'empty-row';
    empty.textContent = 'No wget, curl, or busybox command entries today';
    list.append(empty);
    return;
  }
  for (const [index, item] of items.entries()) {
    const row = document.createElement('li');
    row.className = 'tool-row';
    const rank = document.createElement('span');
    rank.className = 'rank-number';
    rank.textContent = String(index + 1).padStart(2, '0');
    const label = document.createElement('span');
    label.className = 'rank-label';
    label.textContent = item.tool;
    const bar = document.createElement('span');
    bar.className = 'rank-bar';
    const fill = document.createElement('i');
    const maxCount = items[0]?.commands || 1;
    fill.style.width = `${Math.max(4, Math.min(100, (item.commands / maxCount) * 100))}%`;
    bar.append(fill);
    const count = document.createElement('strong');
    count.textContent = `${number.format(item.commands || 0)} cmds`;
    row.append(rank, label, bar, count);
    list.append(row);
  }
}

function renderTimeline() {
  const days = timelineData.slice(-timelineDays);
  const chart = document.querySelector('#timeline-bars');
  chart.replaceChildren();
  const maximum = Math.max(1, ...days.map((item) => item.attacks || 0));
  const total = days.reduce((sum, item) => sum + (item.attacks || 0), 0);
  for (const item of days) {
    const bar = document.createElement('span');
    bar.className = 'timeline-bar';
    const count = item.attacks || 0;
    bar.style.height = count ? `${Math.max(2, (count / maximum) * 100)}%` : '2px';
    const sources = item.unique_sources || 0;
    bar.title = `${item.date}: ${number.format(count)} attacks, ${number.format(sources)} unique sources`;
    bar.setAttribute('aria-label', bar.title);
    chart.append(bar);
  }
  const formatDate = (value) => value ? new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', timeZone: 'UTC' }).format(new Date(`${value}T00:00:00Z`)) : '—';
  document.querySelector('#timeline-total').textContent = number.format(total);
  document.querySelector('#timeline-summary-label').textContent = `attacks · last ${timelineDays} days`;
  document.querySelector('#timeline-start').textContent = formatDate(days[0]?.date);
  document.querySelector('#timeline-end').textContent = formatDate(days.length ? days[days.length - 1].date : null);
  chart.setAttribute('aria-label', `Daily attack events for the last ${timelineDays} days`);
}

function renderWeirdest(data) {
  const title = document.querySelector('#weirdest-title');
  const copy = document.querySelector('#weirdest-copy');
  const badge = document.querySelector('#weirdest-score');
  const foot = document.querySelector('#weirdest-foot');
  if (!data) {
    title.textContent = 'No unusual session recorded today';
    copy.textContent = 'The selector scores command-tool use, shell activity, honeypot logins, and rejected login attempts.';
    badge.textContent = 'NO MATCH';
    foot.textContent = 'Credentials, source addresses, and raw commands are withheld.';
    return;
  }
  title.textContent = data.title || 'Unusual session selected';
  copy.textContent = data.reason || 'Selected by the daily behavior score.';
  badge.textContent = `SCORE ${number.format(data.score || 0)}`;
  const observed = data.observed_at_utc ? new Date(data.observed_at_utc) : null;
  const time = observed ? new Intl.DateTimeFormat('en', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC', timeZoneName: 'short' }).format(observed) : 'UTC';
  const tools = safeArray(data.download_tools);
  foot.textContent = `${number.format(data.event_count || 0)} events · observed ${time}${tools.length ? ` · tools: ${tools.join(', ')}` : ''}`;
}

function formatOffset(value) {
  const seconds = Math.max(0, Number(value) || 0);
  return `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
}

function stopPlayback() {
  if (playbackTimer) window.clearInterval(playbackTimer);
  playbackTimer = null;
  document.querySelector('#playback-toggle').textContent = '▶ Play session';
}

function showPlaybackStep(index) {
  if (!playbackSteps.length) return;
  playbackIndex = Math.max(0, Math.min(index, playbackSteps.length - 1));
  document.querySelectorAll('#playback-steps li[data-step]').forEach((item) => {
    item.classList.toggle('current-step', Number(item.dataset.step) === playbackIndex);
  });
  document.querySelector('#playback-clock').textContent = formatOffset(playbackSteps[playbackIndex].offset_seconds);
}

function renderPlayback(data) {
  const signature = JSON.stringify(data?.steps || []);
  if (signature === playbackSignature) return;
  playbackSignature = signature;
  stopPlayback();
  playbackSteps = safeArray(data?.steps);
  const list = document.querySelector('#playback-steps');
  const toggle = document.querySelector('#playback-toggle');
  list.replaceChildren();
  if (!playbackSteps.length) {
    const empty = document.createElement('li');
    empty.className = 'empty-row';
    empty.textContent = 'No eligible session to replay today';
    list.append(empty);
    document.querySelector('#playback-meta').textContent = 'NO SESSION';
    document.querySelector('#playback-clock').textContent = '00:00';
    toggle.disabled = true;
    return;
  }
  toggle.disabled = false;
  document.querySelector('#playback-meta').textContent = `${number.format(data.event_count || playbackSteps.length)} EVENTS · ${formatOffset(data.duration_seconds)}`;
  for (const [index, step] of playbackSteps.entries()) {
    const item = document.createElement('li');
    item.dataset.step = String(index);
    item.className = `playback-step step-${step.kind || 'activity'}`;
    const elapsed = document.createElement('span');
    elapsed.className = 'playback-offset';
    elapsed.textContent = formatOffset(step.offset_seconds);
    const text = document.createElement('span');
    text.className = 'playback-label';
    text.textContent = step.label;
    item.append(elapsed, text);
    item.addEventListener('click', () => {
      stopPlayback();
      showPlaybackStep(index);
    });
    list.append(item);
  }
  showPlaybackStep(0);
}

document.querySelector('#playback-prev').addEventListener('click', () => {
  stopPlayback();
  showPlaybackStep(Math.max(0, playbackIndex - 1));
});
document.querySelector('#playback-next').addEventListener('click', () => {
  stopPlayback();
  showPlaybackStep(Math.min(playbackSteps.length - 1, playbackIndex + 1));
});
document.querySelector('#playback-toggle').addEventListener('click', () => {
  if (playbackTimer) {
    stopPlayback();
    return;
  }
  if (!playbackSteps.length) return;
  if (playbackIndex >= playbackSteps.length - 1) showPlaybackStep(0);
  document.querySelector('#playback-toggle').textContent = 'Ⅱ Pause';
  playbackTimer = window.setInterval(() => {
    if (playbackIndex >= playbackSteps.length - 1) {
      stopPlayback();
      return;
    }
    showPlaybackStep(playbackIndex + 1);
  }, 1100);
});

document.querySelectorAll('[data-timeline-range]').forEach((button) => {
  button.addEventListener('click', () => {
    timelineDays = Number(button.dataset.timelineRange);
    document.querySelectorAll('[data-timeline-range]').forEach((item) => item.classList.toggle('active', item === button));
    renderTimeline();
  });
});

function applyMetrics(data) {
  const countries = safeArray(data.top_countries);
  const passwords = safeArray(data.top_passwords);
  const usernames = safeArray(data.top_usernames);
  const ports = safeArray(data.top_ports);
  timelineData = safeArray(data.timeline_90d);
  metricText('attacks', number.format(data.attack_events || 0));
  metricText('sources', number.format(data.unique_source_ips || 0));
  metricText('country', countries[0]?.name || countries[0]?.code || '—');
  metricText('country-count', countries[0] ? `${number.format(countries[0].attempts)} attempts` : 'No country data');
  metricText('password', passwords[0]?.value || (passwords[0] ? '(blank)' : '—'));
  metricText('password-count', passwords[0] ? `${number.format(passwords[0].attempts)} attempts` : 'No password attempts');
  document.querySelector('#metric-date').textContent = `${data.date_utc || 'UTC TODAY'}`;
  renderList('countries-list', countries, (item) => item.name || item.code || 'Unknown', countries[0]?.attempts || 1);
  renderList('usernames-list', usernames, (item) => item.value || '(blank)', usernames[0]?.attempts || 1);
  renderList('ports-list', ports, (item) => `${item.port}/TCP`, ports[0]?.attempts || 1);
  renderCommandTools(safeArray(data.command_tools));
  renderTimeline();
  renderWeirdest(data.weirdest_attack);
  renderPlayback(data.attack_playback);
  const updated = data.generated_at_utc ? new Date(data.generated_at_utc) : new Date();
  document.querySelector('#last-updated').textContent = new Intl.DateTimeFormat('en', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC', timeZoneName: 'short' }).format(updated);
  document.querySelector('#sensor-state').textContent = 'METRICS RECEIVED';
  setStatus('live', `Metrics for ${data.date_utc || 'today'} UTC. Aggregate counts only; this page refreshes every five minutes.`);
}

async function refreshMetrics() {
  try {
    const response = await fetch(`${METRICS_URL}${METRICS_URL.includes('?') ? '&' : '?'}_=${Date.now()}`, {
      cache: 'no-store',
      headers: { Accept: 'application/json' }
    });
    if (!response.ok) throw new Error(`Metrics feed returned HTTP ${response.status}`);
    const data = await response.json();
    if (!data || typeof data !== 'object' || !Array.isArray(data.top_countries)) throw new Error('Metrics feed schema is invalid');
    applyMetrics(data);
  } catch (error) {
    const hasData = document.querySelector('[data-metric="attacks"]').textContent !== '—';
    document.querySelector('#sensor-state').textContent = hasData ? 'LAST DATA RETAINED' : 'FEED UNAVAILABLE';
    setStatus(hasData ? 'stale' : 'offline', hasData
      ? 'The feed could not be refreshed. The last received metrics remain visible.'
      : 'Live metrics are not connected yet. This page expects metrics.json from the same web origin.');
    console.warn('Could not refresh observatory metrics:', error.message);
  }
}

function renderLiveAttacks(events, generatedAt) {
  const list = document.querySelector('#live-attack-list');
  list.replaceChildren();
  if (!events.length) {
    const empty = document.createElement('li');
    empty.className = 'empty-row';
    empty.textContent = 'No login attempts recorded in the last 24 hours';
    list.append(empty);
  }
  for (const event of events.slice(0, 10)) {
    const item = document.createElement('li');
    item.className = 'live-attack-row';
    const time = document.createElement('time');
    time.className = 'live-attack-time';
    const timestamp = new Date(event.time_utc);
    time.dateTime = Number.isNaN(timestamp.valueOf()) ? '' : timestamp.toISOString();
    time.textContent = Number.isNaN(timestamp.valueOf())
      ? '—'
      : new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZone: 'UTC' }).format(timestamp);
    const label = document.createElement('span');
    label.className = `live-attack-label ${event.kind === 'success' ? 'success' : ''}`;
    label.textContent = event.kind === 'success' ? 'Honeypot login accepted' : 'SSH login attempt rejected';
    const detail = document.createElement('span');
    detail.className = 'live-attack-detail';
    detail.textContent = 'credentials withheld';
    item.append(time, label, detail);
    list.append(item);
  }
  const update = generatedAt ? new Date(generatedAt) : new Date();
  document.querySelector('#activity-updated').textContent = `UPDATED ${new Intl.DateTimeFormat('en', { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC', timeZoneName: 'short' }).format(update)}`;
}

async function refreshLiveAttacks() {
  try {
    const response = await fetch(`${ACTIVITY_URL}${ACTIVITY_URL.includes('?') ? '&' : '?'}_=${Date.now()}`, {
      cache: 'no-store',
      headers: { Accept: 'application/json' }
    });
    if (!response.ok) throw new Error(`Activity feed returned HTTP ${response.status}`);
    const data = await response.json();
    if (!data || !Array.isArray(data.events)) throw new Error('Activity feed schema is invalid');
    renderLiveAttacks(data.events, data.generated_at_utc);
  } catch (error) {
    const badge = document.querySelector('#activity-updated');
    if (badge.textContent === 'CONNECTING') badge.textContent = 'UNAVAILABLE';
    console.warn('Could not refresh live attack activity:', error.message);
  }
}

refreshMetrics();
window.setInterval(refreshMetrics, REFRESH_MS);
refreshLiveAttacks();
window.setInterval(refreshLiveAttacks, ACTIVITY_REFRESH_MS);
