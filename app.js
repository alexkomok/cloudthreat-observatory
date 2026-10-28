const METRICS_URL = window.OBSERVATORY_METRICS_URL || './metrics.json';
const ACTIVITY_URL = window.OBSERVATORY_ACTIVITY_URL || './activity.json';
const THREAT_INTEL_URL = window.OBSERVATORY_THREAT_INTEL_URL || './threat-intel.json';
const REFRESH_MS = 5 * 60 * 1000;
const ACTIVITY_REFRESH_MS = 15 * 1000;
const number = new Intl.NumberFormat();

const dateLabel = new Intl.DateTimeFormat('en', { month: 'short', day: '2-digit', year: 'numeric', timeZone: 'UTC' });
document.querySelector('#today-date').textContent = `${dateLabel.format(new Date()).toUpperCase()} · UTC`;

const views = {
  overview: [document.querySelector('#overview'), document.querySelector('#feed-notice'), document.querySelector('.live-metrics'), document.querySelector('#live-attacks'), document.querySelector('#timeline'), document.querySelector('#weirdest')],
  rankings: [document.querySelector('#rankings'), document.querySelector('#malware-tools')],
  'threat-intel': [document.querySelector('#threat-intel')],
  playback: [document.querySelector('#playback')],
  about: [document.querySelector('#about')]
};
let timelineData = [];
let timelineDays = 7;
let playbackSteps = [];
let playbackIndex = -1;
let playbackTimer = null;
let playbackSignature = '';
let attackArchive = [];
let selectedSessionIndex = -1;
let selectedSessionFirstSeen = '';

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

function formatObservedDate(value) {
  if (!value) return 'Unknown';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) return 'Unknown';
  return new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' }).format(parsed);
}

function renderThreatIntel(profiles, generatedAt) {
  const list = document.querySelector('#threat-intel-list');
  list.replaceChildren();
  if (!profiles.length) {
    const empty = document.createElement('li');
    empty.className = 'empty-row';
    empty.textContent = 'No repeat sources recorded yet';
    list.append(empty);
  }
  for (const [index, profile] of profiles.entries()) {
    const item = document.createElement('li');
    item.className = 'threat-profile';
    const header = document.createElement('div');
    header.className = 'threat-profile-header';
    const rank = document.createElement('span');
    rank.className = 'threat-rank';
    rank.textContent = `#${String(index + 1).padStart(2, '0')}`;
    const address = document.createElement('code');
    address.className = 'threat-address';
    address.textContent = profile.source_ip || 'Unknown address';
    header.append(rank, address);
    const details = document.createElement('dl');
    details.className = 'threat-profile-details';
    const asn = profile.cloud_provider
      ? `${profile.cloud_provider}${profile.asn ? ` · AS${profile.asn}` : ''}`
      : profile.asn_org
        ? `${profile.asn ? `AS${profile.asn} · ` : ''}${profile.asn_org}`
        : (profile.asn ? `AS${profile.asn}` : 'Unknown');
    const fields = [
      ['First seen', formatObservedDate(profile.first_seen)],
      ['Last seen', formatObservedDate(profile.last_seen)],
      ['Attempts', number.format(profile.attempt_count || 0)],
      ['Country', profile.country_name || profile.country_code || 'Unknown'],
      ['ASN / network', asn]
    ];
    for (const [labelText, valueText] of fields) {
      const field = document.createElement('div');
      field.className = 'threat-detail';
      const label = document.createElement('dt');
      label.textContent = labelText;
      const value = document.createElement('dd');
      value.textContent = valueText;
      field.append(label, value);
      details.append(field);
    }
    item.append(header, details);
    list.append(item);
  }
  const updated = generatedAt ? new Date(generatedAt) : new Date();
  document.querySelector('#threat-intel-updated').textContent = `UPDATED ${new Intl.DateTimeFormat('en', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC', timeZoneName: 'short' }).format(updated)}`;
}

async function refreshThreatIntel() {
  try {
    const response = await fetch(`${THREAT_INTEL_URL}${THREAT_INTEL_URL.includes('?') ? '&' : '?'}_=${Date.now()}`, {
      cache: 'no-store',
      headers: { Accept: 'application/json' }
    });
    if (!response.ok) throw new Error(`Threat Intel feed returned HTTP ${response.status}`);
    const data = await response.json();
    if (!data || !Array.isArray(data.repeat_offenders)) throw new Error('Threat Intel feed schema is invalid');
    renderThreatIntel(data.repeat_offenders, data.generated_at_utc);
  } catch (error) {
    const badge = document.querySelector('#threat-intel-updated');
    if (badge.textContent === 'CONNECTING') badge.textContent = 'UNAVAILABLE';
    console.warn('Could not refresh Threat Intel profiles:', error.message);
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
    title.textContent = 'No featured session yet';
    copy.textContent = 'The featured attack is selected from today’s most interesting recorded sessions.';
    badge.textContent = 'NO MATCH';
    foot.textContent = 'Credentials, source addresses, and raw commands are withheld.';
    return;
  }
  title.textContent = data.title || 'Unusual session selected';
  copy.textContent = data.reason || 'Selected from today’s session archive using observed activity signals.';
  badge.textContent = `SCORE ${number.format(data.score || 0)}`;
  const observed = data.observed_at_utc ? new Date(data.observed_at_utc) : null;
  const time = observed ? new Intl.DateTimeFormat('en', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC', timeZoneName: 'short' }).format(observed) : 'UTC';
  const tools = safeArray(data.download_tools);
  foot.textContent = `${number.format(data.event_count || 0)} events · observed ${time}${tools.length ? ` · tools: ${tools.join(', ')}` : ''}`;
}

function formatDuration(seconds) {
  const value = Math.max(0, Number(seconds) || 0);
  if (value < 60) return `${value}s`;
  return `${Math.floor(value / 60)}m ${String(value % 60).padStart(2, '0')}s`;
}

function formatSessionTime(value) {
  if (!value) return 'Time unknown';
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return 'Time unknown';
  return new Intl.DateTimeFormat('en', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC', timeZoneName: 'short' }).format(date);
}

function renderSelectedSession(session, index) {
  selectedSessionIndex = index;
  selectedSessionFirstSeen = session?.first_seen_utc || '';
  document.querySelectorAll('.session-list-button').forEach((button) => {
    const active = Number(button.dataset.sessionIndex) === index;
    button.classList.toggle('selected', active);
    button.setAttribute('aria-pressed', String(active));
  });
  if (!session) {
    document.querySelector('#selected-feature-label').textContent = 'FEATURED ATTACK OF THE DAY';
    document.querySelector('#selected-title').textContent = 'No session recorded today';
    document.querySelector('#selected-category').textContent = 'NO SESSION';
    document.querySelector('#selected-category').className = 'category-badge';
    document.querySelector('#selected-time').textContent = 'UTC TODAY';
    document.querySelector('#selected-summary').textContent = 'No eligible Cowrie session is available for the current UTC day.';
    document.querySelector('#summary-duration').textContent = '—';
    document.querySelector('#summary-commands').textContent = '—';
    document.querySelector('#summary-login').textContent = '—';
    document.querySelector('#summary-downloads').textContent = '—';
    document.querySelector('#summary-score').textContent = '—';
    renderPlayback(null);
    return;
  }
  document.querySelector('#selected-feature-label').textContent = index === 0 ? 'FEATURED ATTACK OF THE DAY' : 'SELECTED SESSION';
  document.querySelector('#selected-title').textContent = session.title || 'Cowrie session';
  const category = document.querySelector('#selected-category');
  category.textContent = session.category_label || 'Activity';
  category.className = `category-badge category-${session.category || 'activity'}`;
  document.querySelector('#selected-time').textContent = `${formatSessionTime(session.first_seen_utc)} · ${number.format(session.event_count || 0)} logged events`;
  document.querySelector('#selected-summary').textContent = session.summary || 'A redacted summary of observed session activity.';
  document.querySelector('#summary-duration').textContent = formatDuration(session.duration_seconds);
  document.querySelector('#summary-commands').textContent = number.format(session.commands || 0);
  document.querySelector('#summary-login').textContent = session.login_successes
    ? `Succeeded (${number.format(session.login_successes)})`
    : session.login_failures ? `Rejected (${number.format(session.login_failures)})` : 'Not observed';
  document.querySelector('#summary-downloads').textContent = session.downloads
    ? number.format(session.downloads)
    : session.download_tool_events ? `${number.format(session.download_tool_events)} attempted` : '0';
  document.querySelector('#summary-score').textContent = `${number.format(session.score || 0)} / 99`;
  document.querySelector('#playback-meta').textContent = `${number.format(session.steps?.length || 0)} TIMELINE EVENTS`;
  renderPlayback(session);
}

function renderSessionArchive(data) {
  const stats = data.session_stats || {};
  document.querySelector('#sessions-today').textContent = number.format(stats.sessions_today || 0);
  document.querySelector('#successful-logins').textContent = number.format(stats.successful_logins_today || 0);
  document.querySelector('#malware-downloads').textContent = number.format(stats.file_downloads_today || 0);
  document.querySelector('#unique-attackers').textContent = number.format(stats.unique_attackers_today || 0);
  attackArchive = safeArray(data.attack_archive);
  const list = document.querySelector('#session-list');
  list.replaceChildren();
  document.querySelector('#archive-count').textContent = stats.sessions_today
    ? `TOP ${number.format(attackArchive.length)} OF ${number.format(stats.sessions_today)}`
    : 'NO SESSIONS';
  if (!attackArchive.length) {
    const empty = document.createElement('li');
    empty.className = 'empty-row';
    empty.textContent = 'No eligible sessions recorded today';
    list.append(empty);
    renderSelectedSession(null, -1);
    return;
  }
  for (const [index, session] of attackArchive.entries()) {
    const item = document.createElement('li');
    item.className = 'session-list-item';
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'session-list-button';
    button.dataset.sessionIndex = String(index);
    button.setAttribute('aria-pressed', 'false');
    const top = document.createElement('span');
    top.className = 'session-list-top';
    const rank = document.createElement('span');
    rank.className = 'session-rank';
    rank.textContent = `#${String(index + 1).padStart(2, '0')}`;
    const pill = document.createElement('span');
    pill.className = `category-pill category-${session.category || 'activity'}`;
    pill.textContent = session.category_label || 'Activity';
    const time = document.createElement('time');
    time.className = 'session-list-time';
    time.dateTime = session.first_seen_utc || '';
    time.textContent = formatSessionTime(session.first_seen_utc);
    top.append(rank, pill, time);
    const title = document.createElement('strong');
    title.className = 'session-list-title';
    title.textContent = session.title || 'Cowrie session';
    const facts = document.createElement('span');
    facts.className = 'session-list-facts';
    facts.textContent = `${number.format(session.commands || 0)} commands · ${number.format(session.login_attempts || 0)} login attempts · score ${number.format(session.score || 0)}`;
    button.append(top, title, facts);
    button.addEventListener('click', () => {
      stopPlayback();
      renderSelectedSession(attackArchive[index], index);
    });
    item.append(button);
    list.append(item);
  }
  const priorIndex = attackArchive.findIndex((session) => session.first_seen_utc === selectedSessionFirstSeen);
  const nextIndex = priorIndex >= 0 ? priorIndex : 0;
  renderSelectedSession(attackArchive[nextIndex], nextIndex);
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
  const signature = JSON.stringify([data?.first_seen_utc || '', data?.steps || []]);
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
    document.querySelector('#playback-meta').textContent = 'NO TIMELINE';
    document.querySelector('#playback-clock').textContent = '00:00';
    toggle.disabled = true;
    return;
  }
  toggle.disabled = false;
  document.querySelector('#playback-meta').textContent = `${number.format(data.event_count || playbackSteps.length)} LOGGED EVENTS`;
  for (const [index, step] of playbackSteps.entries()) {
    const item = document.createElement('li');
    item.dataset.step = String(index);
    item.className = `playback-step step-${step.kind || 'activity'}`;
    const main = document.createElement('div');
    main.className = 'playback-step-main';
    const elapsed = document.createElement('span');
    elapsed.className = 'playback-offset';
    elapsed.textContent = formatOffset(step.offset_seconds);
    const text = document.createElement('span');
    text.className = 'playback-label';
    text.textContent = step.label;
    main.append(elapsed, text);
    item.append(main);
    if (safeArray(step.children).length) {
      const expand = document.createElement('button');
      expand.className = 'step-expand';
      expand.type = 'button';
      expand.textContent = 'Expand';
      expand.setAttribute('aria-expanded', 'false');
      const children = document.createElement('ol');
      children.className = 'playback-substeps';
      children.hidden = true;
      for (const child of step.children) {
        const childRow = document.createElement('li');
        const childOffset = document.createElement('time');
        childOffset.textContent = formatOffset(child.offset_seconds);
        const childText = document.createElement('span');
        childText.textContent = child.label;
        childRow.append(childOffset, childText);
        children.append(childRow);
      }
      expand.addEventListener('click', () => {
        const isExpanded = expand.getAttribute('aria-expanded') === 'true';
        expand.setAttribute('aria-expanded', String(!isExpanded));
        children.hidden = isExpanded;
        expand.textContent = isExpanded ? 'Expand' : 'Collapse';
      });
      item.append(expand, children);
    }
    item.addEventListener('click', () => {
      stopPlayback();
      showPlaybackStep(index);
    });
    item.querySelector('.step-expand')?.addEventListener('click', (event) => event.stopPropagation());
    list.append(item);
  }
  showPlaybackStep(0);
}

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
  const loginAttempts = Number(data.login_attempts) || 0;
  const passwordShare = passwords[0] && loginAttempts > 0
    ? `${((passwords[0].attempts / loginAttempts) * 100).toFixed(1)}% of all login attempts`
    : loginAttempts > 0 ? 'No password attempts today' : 'No login attempts today';
  metricText('password-share', passwordShare);
  metricText('username', usernames[0]?.value || (usernames[0] ? '(blank)' : '—'));
  metricText('username-count', usernames[0] ? `${number.format(usernames[0].attempts)} attempts` : 'No username attempts');
  const usernameShare = usernames[0] && loginAttempts > 0
    ? `${((usernames[0].attempts / loginAttempts) * 100).toFixed(1)}% of all login attempts`
    : loginAttempts > 0 ? 'No username attempts today' : 'No login attempts today';
  metricText('username-share', usernameShare);
  document.querySelector('#metric-date').textContent = `${data.date_utc || 'UTC TODAY'}`;
  renderList('countries-list', countries, (item) => item.name || item.code || 'Unknown', countries[0]?.attempts || 1);
  renderList('usernames-list', usernames, (item) => item.value || '(blank)', usernames[0]?.attempts || 1);
  renderList('passwords-list', passwords, (item) => item.value || '(blank)', passwords[0]?.attempts || 1);
  renderList('ports-list', ports, (item) => `${item.port}/TCP`, ports[0]?.attempts || 1);
  renderCommandTools(safeArray(data.command_tools));
  renderTimeline();
  renderWeirdest(data.weirdest_attack);
  renderSessionArchive(data);
  const updated = data.generated_at_utc ? new Date(data.generated_at_utc) : new Date();
  document.querySelector('#last-updated').textContent = new Intl.DateTimeFormat('en', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC', timeZoneName: 'short' }).format(updated);
  document.querySelector('#sensor-state').textContent = 'METRICS RECEIVED';
  setStatus('live', `Metrics for ${data.date_utc || 'today'} UTC. Session summaries are redacted; raw credentials, addresses, and commands are withheld. Refreshes every five minutes.`);
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
refreshThreatIntel();
window.setInterval(refreshThreatIntel, REFRESH_MS);

