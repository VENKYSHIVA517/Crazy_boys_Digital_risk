const loginScreen = document.querySelector('#login-screen');
const platformShell = document.querySelector('#platform-shell');
const pageViews = [...document.querySelectorAll('[data-page]')];
const navLinks = [...document.querySelectorAll('[data-view-link]')];
const alerts = [
    { id: 'a1', title: 'Lookalike sign-in page', subject: 'secure-account-verify.co', source: 'Browser link', level: 'high', category: 'Phishing', time: '12 min ago', status: 'New', findings: ['The domain combines account and verification lure terms.', 'The site asks visitors to sign in before viewing a shared document.'], recommendation: 'Do not enter credentials. Close the page and open the service from a saved bookmark instead.' },
    { id: 'a2', title: 'Unexpected invoice request', subject: 'Invoice #8041 — review needed', source: 'Email sample', level: 'medium', category: 'Email scam', time: '1 hr ago', status: 'New', findings: ['The message uses urgent payment language.', 'The sender details do not match the claimed billing team.'], recommendation: 'Verify the invoice with the sender using a contact method you already trust.' },
    { id: 'a3', title: 'Unverified app publisher', subject: 'QuickPDF Converter', source: 'App inventory', level: 'high', category: 'App risk', time: '3 hr ago', status: 'Reviewing', findings: ['The sample app requests broad file access.', 'The publisher identity has not been verified in this demo.'], recommendation: 'Check the publisher and app permissions in the official store before installing.' },
    { id: 'a4', title: 'Password-reset text message', subject: 'Action required to keep your account', source: 'SMS sample', level: 'low', category: 'Message review', time: 'Yesterday', status: 'Reviewed', findings: ['No direct credential request or suspicious destination was found in this sample.'], recommendation: 'If you did not request a reset, open the service directly and review account activity.' }
];
const activitySources = [
    { name: 'Browser activity', detail: 'Links and web destinations', icon: '↗', state: 'Demo only', description: 'Manual URL checks available', action: 'Review scanner', view: 'url-scanner' },
    { name: 'Email inbox', detail: 'Phishing and sender signals', icon: '✉', state: 'Not connected', description: 'Paste text for a local review', action: 'Open scanner', view: 'messages' },
    { name: 'SMS messages', detail: 'Smishing and payment lures', icon: '▤', state: 'Not connected', description: 'Paste text for a local review', action: 'Open scanner', view: 'messages' },
    { name: 'Mobile apps', detail: 'Publisher and permission review', icon: '▣', state: 'Sample inventory', description: 'No device access', action: 'View inventory', view: 'apps' },
    { name: 'Social & transactions', detail: 'Impersonation and payment scams', icon: '◎', state: 'Not connected', description: 'No account integrations', action: 'Review signals', view: 'brands' }
];
const intelSignals = [
    { category: 'impersonation', title: 'Lookalike domains imitate shared-file portals', summary: 'A sample campaign uses login prompts and subtle spelling changes to collect credentials.', severity: 'High relevance', age: '18 min ago', source: 'Brand impersonation' },
    { category: 'phishing', title: 'Fake delivery notices request small payments', summary: 'Unexpected package-fee messages may lead to credential forms or payment collection pages.', severity: 'Elevated', age: '2 hr ago', source: 'Message scams' },
    { category: 'malware', title: 'Unverified installers bundle extra software', summary: 'Download buttons on copycat utility pages may lead to unwanted or unsafe installers.', severity: 'Moderate', age: 'Today', source: 'Application safety' },
    { category: 'phishing', title: 'Password-reset lures use short deadlines', summary: 'Messages that combine account threats, urgency, and an unfamiliar link deserve extra scrutiny.', severity: 'Elevated', age: 'Today', source: 'Credential theft' }
];
const appInventory = [
    { name: 'QuickPDF Converter', publisher: 'Publisher not verified', source: 'Direct download', permissions: 'Files, notifications', level: 'high', glyph: '▣' },
    { name: 'Northstar Authenticator', publisher: 'Northstar Labs', source: 'Official app store', permissions: 'Camera', level: 'low', glyph: '◈' },
    { name: 'Flash Rewards+', publisher: 'New publisher', source: 'Unknown source', permissions: 'Contacts, SMS', level: 'high', glyph: '✳' },
    { name: 'Cloud Notes', publisher: 'Cloud Notes Inc.', source: 'Official app store', permissions: 'Files', level: 'medium', glyph: '▤' }
];
const suspiciousTerms = /verify|account|password|login|secure|update|wallet|bank|payment|invoice|gift.?card|crypto|suspend|confirm/i;
const urgentTerms = /urgent|immediately|within\s+\d+\s+hours?|act now|final warning|expires today|account (?:will be|has been) (?:locked|suspended)/i;
const credentialTerms = /password|sign[\s-]?in|log[\s-]?in|credentials|verify your account|confirm your identity|one.?time code/i;
const shortenedDomains = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rb.gy', 'rebrand.ly', 'tiny.cc'];
const riskyTlds = ['.zip', '.mov', '.click', '.top', '.work', '.country', '.gq', '.tk'];
let currentMessageMode = 'email';
let activeAlertFilter = 'all';
let activeIntelFilter = 'all';
let currentScan = null;
let customScanCount = 0;
let monitoringActive = true;
let profileName = 'Jordan Davis';
const preferences = { highRiskAlerts: true, sampleAdvisories: true, reducedMotion: false };

function riskLevel(score) {
    if (score >= 60) return 'high';
    if (score >= 30) return 'medium';
    return 'low';
}

function analyzeUrl(value) {
    let candidate = value.trim();
    if (!/^https?:\/\//i.test(candidate)) candidate = `https://${candidate}`;
    let url;
    try {
        url = new URL(candidate);
        if (!url.hostname.includes('.') && url.hostname !== 'localhost') throw new Error('Invalid host');
    } catch {
        return { score: 65, findings: ['This does not look like a valid website address.'], subject: value.trim() };
    }
    let score = 0;
    const findings = [];
    const host = url.hostname.toLowerCase();
    const fullAddress = `${host}${url.pathname}${url.search}`;
    const addFinding = (points, message) => { score += points; findings.push(message); };
    if (url.protocol !== 'https:') addFinding(12, 'The link does not use encrypted HTTPS.');
    if (url.username || url.password) addFinding(40, 'The address contains an unexpected username or password.');
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.startsWith('[')) addFinding(32, 'The site uses a raw IP address instead of a recognizable domain.');
    if (host.split('.').some(part => part.startsWith('xn--'))) addFinding(25, 'The domain uses encoded characters that can disguise lookalike text.');
    if (shortenedDomains.includes(host)) addFinding(18, 'A link-shortening service hides the final destination.');
    if (suspiciousTerms.test(fullAddress)) addFinding(12, 'The address includes words commonly used in account or payment lures.');
    const lureTerms = host.split(/[^a-z0-9]+/).filter(part => /^(?:verify|account|password|login|secure|update|wallet|bank|payment|invoice|giftcard|crypto|suspend|confirm)$/.test(part));
    if (lureTerms.length >= 2) addFinding(lureTerms.length >= 3 ? 48 : 20, 'The domain combines multiple account or payment lure terms.');
    if (host.split('.').length > 4) addFinding(10, 'The address has an unusually deep subdomain structure.');
    if ((host.match(/-/g) || []).length >= 3) addFinding(10, 'The domain contains several hyphens, a pattern seen in lookalike sites.');
    if (riskyTlds.some(tld => host.endsWith(tld))) addFinding(12, 'The domain uses a top-level domain that is often abused.');
    if (url.href.length > 180) addFinding(6, 'The address is unusually long and may conceal its destination.');
    if (findings.length === 0) findings.push('No common warning signs were found in this address.');
    return { score: Math.min(score, 100), findings, subject: host };
}

function analyzeMessage(value, mode) {
    const message = value.trim();
    const normalized = message.replace(/\s+/g, ' ');
    const findings = [];
    let score = 0;
    const addFinding = (points, description) => { score += points; findings.push(description); };
    if (urgentTerms.test(normalized)) addFinding(20, 'The message pressures you to act immediately.');
    if (credentialTerms.test(normalized)) addFinding(24, 'The message asks for sign-in details, identity checks, or security codes.');
    if (/gift.?card|wire transfer|crypto(?:currency)?|payment details|bank details|pay a small fee/i.test(normalized)) addFinding(22, 'The message mentions an unusual payment or money transfer.');
    if (/dear customer|dear user|valued customer|undisclosed recipients/i.test(normalized)) addFinding(10, 'The greeting is generic rather than addressed to you.');
    if (/from:\s*[^\n]*@(gmail|outlook|yahoo|protonmail)\.[^\s>]+/i.test(message) && /from:\s*[^\n]*(bank|support|security|billing|payroll)/i.test(message)) addFinding(18, 'The sender name suggests an organization but uses a personal email domain.');
    if (/https?:\/\/[^\s<>"']+\s*\(([^)]+)\)/i.test(message)) addFinding(16, 'A displayed link may not match its actual destination.');
    const links = message.match(/(?:https?:\/\/|www\.)[^\s<>"']+|(?:[\w-]+\.)+[a-z]{2,}(?:\/[^\s<>"']*)?/gi) || [];
    for (const link of links.slice(0, 3)) {
        const result = analyzeUrl(link.replace(/[),.;!?]+$/, ''));
        if (result.score >= 20) {
            score += Math.min(15, Math.round(result.score / 3));
            findings.push(`An included link has warning signs: ${result.findings[0].toLowerCase()}`);
        }
    }
    if (mode === 'sms' && /\b(?:reply|text back|call this number)\b/i.test(normalized) && /\b(?:code|pin|password|payment)\b/i.test(normalized)) addFinding(12, 'The text asks you to respond with sensitive information.');
    if (findings.length === 0) findings.push('No common phishing language or risky links were detected.');
    return { score: Math.min(score, 100), findings, subject: message.split('\n')[0].slice(0, 48) || `${mode.toUpperCase()} message` };
}

function setView(view) {
    if (!pageViews.some(section => section.dataset.page === view)) return;
    pageViews.forEach(section => section.classList.toggle('is-visible', section.dataset.page === view));
    navLinks.forEach(link => {
        const active = link.dataset.viewLink === view;
        link.classList.toggle('is-active', active);
        if (active) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
    });
    const title = navLinks.find(link => link.dataset.viewLink === view)?.textContent.trim() || 'Overview';
    document.querySelector('#topbar-title').textContent = title.replace(/\d+/g, '').trim();
    history.replaceState(null, '', `#${view}`);
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function createElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
}

function renderTrendChart(target, values, labels) {
    target.replaceChildren(...values.map((value, index) => {
        const column = createElement('div', 'chart-column');
        const bar = createElement('i');
        bar.style.height = `${Math.max(7, value)}%`;
        bar.title = `${labels[index]}: ${Math.round(value / 14)} sample signals`;
        column.append(bar, createElement('span', '', labels[index]));
        return column;
    }));
}

function renderOverviewAlerts() {
    const host = document.querySelector('#overview-alerts');
    const recent = alerts.slice(0, 3);
    host.replaceChildren(...recent.map(alert => {
        const card = createElement('article', `overview-alert${preferences.highRiskAlerts && alert.level === 'high' ? ' high-risk-emphasis' : ''}`);
        const top = createElement('div', 'alert-card-top');
        top.append(createElement('span', 'alert-type', alert.category), createElement('span', `risk-label ${alert.level}`, `${alert.level[0].toUpperCase()}${alert.level.slice(1)}`));
        card.append(top, createElement('h3', '', alert.title), createElement('p', '', `${alert.subject} · ${alert.time}`));
        return card;
    }));
}

function renderSources() {
    const host = document.querySelector('#source-list');
    host.replaceChildren(...activitySources.map(source => {
        const row = createElement('article', 'source-row');
        const identity = createElement('div', 'source-identity');
        identity.append(createElement('span', 'source-icon', source.icon));
        const copy = createElement('div');
        copy.append(createElement('h3', '', source.name), createElement('p', '', source.detail));
        identity.append(copy);
        const state = createElement('div', 'source-state');
        state.append(createElement('strong', '', source.state), createElement('p', '', source.description));
        const action = createElement('button', `source-action${source.state === 'Demo only' ? ' is-demo' : ''}`, source.action);
        action.type = 'button';
        action.dataset.go = source.view;
        row.append(identity, state, action);
        return row;
    }));
}

function renderTimeline() {
    const host = document.querySelector('#monitoring-activity');
    const entries = [
        ['Demo environment ready. No external sources are connected.', 'Just now'],
        ['Sample browser activity reviewed by local heuristics.', 'Today'],
        ['Email and SMS scanners are available for manual checks.', 'Today']
    ];
    host.replaceChildren(...entries.map(([text, time]) => {
        const row = createElement('div', 'timeline-row');
        row.append(createElement('i'), createElement('span', '', text), createElement('small', '', time));
        return row;
    }));
}

function renderIntel(filter = activeIntelFilter) {
    activeIntelFilter = filter;
    const host = document.querySelector('#intel-list');
    if (!preferences.sampleAdvisories) {
        host.replaceChildren(createElement('div', 'empty-state', 'Sample advisories are hidden in Settings.'));
        return;
    }
    const shown = filter === 'all' ? intelSignals : intelSignals.filter(signal => signal.category === filter);
    if (!shown.length) {
        host.replaceChildren(createElement('div', 'empty-state', 'No sample signals in this category.'));
        return;
    }
    host.replaceChildren(...shown.map(signal => {
        const card = createElement('article', 'intel-card');
        card.dataset.category = signal.category;
        card.append(createElement('span', 'intel-symbol', signal.category === 'malware' ? '⌑' : signal.category === 'impersonation' ? '◎' : '!'));
        const body = createElement('div');
        body.append(createElement('h2', '', signal.title), createElement('p', '', signal.summary));
        const meta = createElement('div', 'intel-meta');
        meta.append(createElement('span', '', signal.source), createElement('span', '', signal.age));
        body.append(meta);
        card.append(body, createElement('span', 'intel-severity', signal.severity));
        return card;
    }));
}

function renderApps() {
    const host = document.querySelector('#app-table-body');
    host.replaceChildren(...appInventory.map(app => {
        const row = createElement('tr');
        const appCell = createElement('td');
        const identity = createElement('div', 'app-cell');
        identity.append(createElement('span', 'app-cell-icon', app.glyph));
        const name = createElement('div');
        name.append(createElement('strong', '', app.name), createElement('small', '', app.publisher));
        identity.append(name);
        appCell.append(identity);
        const source = createElement('td', '', app.source);
        const permissions = createElement('td', '', app.permissions);
        const riskCell = createElement('td');
        riskCell.append(createElement('span', `table-risk ${app.level}`, `${app.level[0].toUpperCase()}${app.level.slice(1)} review`));
        const actionCell = createElement('td');
        const action = createElement('button', 'review-button', 'Details');
        action.type = 'button';
        action.dataset.appName = app.name;
        actionCell.append(action);
        row.append(appCell, source, permissions, riskCell, actionCell);
        return row;
    }));
}

function renderBrandResults(brand) {
    const normalized = brand.trim().toLowerCase().replace(/[^a-z0-9]/g, '') || 'brand';
    const results = [
        { domain: `${normalized}-secure.example`, reason: 'Adds account-security language to the brand name.', level: 'high' },
        { domain: `account-${normalized}.example`, reason: 'Combines the brand with a credential-related word.', level: 'medium' },
        { domain: `${normalized}support.example`, reason: 'Uses a support-style variation that may confuse visitors.', level: 'medium' }
    ];
    document.querySelector('#brand-results-title').textContent = `Signals for ${brand.trim() || 'brand'}`;
    document.querySelector('#brand-result-count').textContent = `${results.length} sample signals`;
    const host = document.querySelector('#brand-results');
    host.replaceChildren(...results.map(result => {
        const row = createElement('article', 'brand-result');
        row.append(createElement('span', 'brand-result-icon', '◎'));
        const copy = createElement('div');
        copy.append(createElement('h3', '', result.domain), createElement('p', '', result.reason));
        row.append(copy, createElement('span', `risk-label ${result.level}`, `${result.level[0].toUpperCase()}${result.level.slice(1)}`));
        return row;
    }));
}

function renderAlerts(filter = activeAlertFilter) {
    activeAlertFilter = filter;
    const filtered = alerts.filter(alert => filter === 'all' || (filter === 'new' ? alert.status === 'New' : alert.level === filter));
    const host = document.querySelector('#alerts-list');
    document.querySelector('#all-alert-count').textContent = String(alerts.length).padStart(2, '0');
    document.querySelector('#nav-alert-count').textContent = alerts.filter(alert => alert.status === 'New').length;
    document.querySelector('#threat-count').textContent = String(alerts.filter(alert => alert.level !== 'low').length).padStart(2, '0');
    document.querySelector('#report-threat-count').textContent = String(alerts.filter(alert => alert.level !== 'low').length).padStart(2, '0');
    document.querySelector('#report-high-count').textContent = String(alerts.filter(alert => alert.level === 'high').length).padStart(2, '0');
    document.querySelector('#topbar-alert-dot').hidden = !alerts.some(alert => alert.status === 'New');
    if (!filtered.length) {
        host.replaceChildren(createElement('div', 'empty-state', 'Nothing to review in this filter.'));
        return;
    }
    host.replaceChildren(...filtered.map(alert => {
        const card = createElement('article', 'alert-card');
        card.dataset.level = alert.level;
        card.classList.toggle('high-risk-emphasis', preferences.highRiskAlerts && alert.level === 'high');
        const top = createElement('div', 'alert-card-top');
        const title = createElement('div', 'alert-card-title');
        title.append(createElement('span', `risk-label ${alert.level}`, `${alert.level[0].toUpperCase()}${alert.level.slice(1)}`), createElement('h2', '', alert.title));
        top.append(title, createElement('span', 'alert-type', alert.category));
        card.append(top, createElement('p', '', `${alert.subject} — ${alert.findings[0]}`));
        const meta = createElement('div', 'alert-card-meta');
        meta.append(createElement('span', '', alert.source), createElement('span', '', alert.time));
        card.append(meta);
        const actions = createElement('div', 'alert-actions');
        const select = document.createElement('select');
        select.setAttribute('aria-label', `Choose response for ${alert.title}`);
        ['Warn', 'Block', 'Quarantine', 'Report'].forEach(action => select.add(new Option(action, action.toLowerCase())));
        const apply = createElement('button', '', 'Apply action');
        apply.type = 'button';
        apply.dataset.alertAction = alert.id;
        apply.dataset.actionSelect = 'true';
        const details = createElement('button', '', 'Details');
        details.type = 'button';
        details.dataset.alertDetails = alert.id;
        const status = createElement('span', `review-status${alert.status === 'Reviewed' ? ' is-reviewed' : ''}`, alert.status);
        actions.append(select, apply, details, status);
        card.append(actions);
        return card;
    }));
    renderOverviewAlerts();
}

function addNewAlert(result, mode) {
    const type = mode === 'url' ? 'Website link' : mode === 'email' ? 'Email message' : 'SMS message';
    const alert = {
        id: `scan-${Date.now()}`,
        title: result.level === 'high' ? 'High-risk activity flagged' : 'Potential risk needs review',
        subject: result.subject,
        source: type,
        level: result.level,
        category: mode === 'url' ? 'URL scan' : 'Message scan',
        time: 'Just now',
        status: 'New',
        findings: result.findings,
        recommendation: result.level === 'high' ? 'Avoid opening the link or replying. Use a trusted route to contact the organization.' : 'Pause before acting and verify the sender or destination independently.'
    };
    alerts.unshift(alert);
    if (alerts.length > 20) alerts.pop();
    renderAlerts(activeAlertFilter);
    return alert;
}

function renderScanResult(host, result, mode) {
    const level = riskLevel(result.score);
    result.level = level;
    currentScan = result;
    const box = createElement('div', `scan-score-box ${level}`);
    box.append(createElement('strong', '', String(result.score)), createElement('span', '', 'RISK SCORE'));
    const copy = createElement('div', 'scan-copy');
    const top = createElement('div', 'scan-copy-top');
    const title = level === 'low' ? 'No major warning signs found' : level === 'medium' ? 'Some warning signs found' : 'Potential threat detected';
    top.append(createElement('h3', '', title), createElement('span', `risk-label ${level}`, `${level[0].toUpperCase()}${level.slice(1)} risk`));
    const type = mode === 'url' ? 'Website' : mode === 'email' ? 'Email' : 'SMS';
    copy.append(top, createElement('p', '', `${type} review for “${result.subject}”. This browser-side heuristic is not a reputation lookup.`));
    const findings = createElement('ul', 'scan-findings');
    result.findings.forEach(finding => findings.append(createElement('li', '', finding)));
    copy.append(findings);
    const actions = createElement('div', 'scan-actions');
    if (level === 'low') {
        const proceed = createElement('button', 'continue-action', 'Continue carefully');
        proceed.type = 'button';
        proceed.dataset.safeContinue = 'true';
        actions.append(proceed);
    } else {
        if (!result.alertId) result.alertId = addNewAlert(result, mode).id;
        ['Warn', 'Block', 'Quarantine', 'Report'].forEach(actionLabel => {
            const action = createElement('button', '', actionLabel);
            action.type = 'button';
            action.dataset.scanAction = actionLabel.toLowerCase();
            actions.append(action);
        });
    }
    copy.append(actions);
    host.replaceChildren(box, copy);
    host.hidden = false;
}

function showToast(message) {
    const region = document.querySelector('#toast-region');
    const toast = createElement('div', 'toast', message);
    region.append(toast);
    window.setTimeout(() => toast.remove(), 3500);
}

function openAlertDetails(alert) {
    const content = document.querySelector('#threat-dialog-content');
    const wrapper = createElement('div', 'dialog-content');
    wrapper.append(createElement('span', `risk-label ${alert.level}`, `${alert.level[0].toUpperCase()}${alert.level.slice(1)} risk`), createElement('h2', '', alert.title), createElement('p', '', `${alert.subject} · ${alert.source} · ${alert.time}`));
    const list = createElement('ul', 'scan-findings');
    alert.findings.forEach(finding => list.append(createElement('li', '', finding)));
    wrapper.append(list, createElement('div', 'dialog-finding', `Why it matters: ${alert.findings.join(' ')}`), createElement('p', 'dialog-recommendation', `Suggested next step: ${alert.recommendation}`));
    content.replaceChildren(wrapper);
    document.querySelector('#threat-dialog').showModal();
}

function updateProfile(name, email) {
    const cleanName = name.trim() || email.split('@')[0] || 'Jordan Davis';
    profileName = cleanName;
    const firstName = cleanName.split(/[ ._-]/)[0];
    document.querySelector('#greeting-name').textContent = firstName;
    document.querySelector('#account-name').textContent = cleanName;
    const initials = cleanName.split(/\s+/).slice(0, 2).map(part => part[0]?.toUpperCase()).join('') || 'JD';
    document.querySelector('#topbar-avatar').textContent = initials;
    document.querySelectorAll('.workspace-avatar').forEach(avatar => { avatar.textContent = initials; });
}

document.querySelector('#login-form').addEventListener('submit', event => {
    event.preventDefault();
    const email = document.querySelector('#login-email').value.trim();
    const name = email.split('@')[0].replace(/[._-]+/g, ' ').replace(/\b\w/g, letter => letter.toUpperCase());
    updateProfile(name, email);
    loginScreen.hidden = true;
    platformShell.hidden = false;
    setView(location.hash.slice(1) || 'overview');
});

document.querySelector('#sign-out').addEventListener('click', () => {
    platformShell.hidden = true;
    loginScreen.hidden = false;
    document.querySelector('#login-password').value = '';
    showToast('Signed out of the local demo workspace.');
});

navLinks.forEach(link => link.addEventListener('click', event => {
    event.preventDefault();
    setView(link.dataset.viewLink);
}));
document.addEventListener('click', event => {
    const go = event.target.closest('[data-go]');
    if (go) setView(go.dataset.go);
});
document.querySelector('#alerts-shortcut').addEventListener('click', () => setView('alerts'));
document.querySelector('#monitoring-toggle').addEventListener('click', () => {
    monitoringActive = !monitoringActive;
    document.querySelector('#monitoring-toggle-label').textContent = monitoringActive ? 'Pause demo' : 'Resume demo';
    document.querySelector('#topbar-monitor-status').textContent = monitoringActive ? 'Demo active' : 'Demo paused';
    document.querySelector('.monitor-chip i').style.background = monitoringActive ? '#59ad7f' : '#b4beb7';
    document.querySelector('.sidebar-demo strong').textContent = monitoringActive ? 'Demo monitoring' : 'Monitoring paused';
    showToast(monitoringActive ? 'Demo monitoring resumed.' : 'Demo monitoring paused. No integrations are connected.');
});

document.querySelectorAll('[data-scan-form]').forEach(form => form.addEventListener('submit', event => {
    event.preventDefault();
    const value = form.querySelector('[name="target"]').value.trim();
    if (!value) return;
    const mode = form.dataset.scanMode;
    const result = mode === 'url' ? analyzeUrl(value) : analyzeMessage(value, mode);
    const host = document.querySelector(mode === 'url' ? '#url-result' : '#message-result');
    customScanCount += 1;
    document.querySelector('#activity-count').textContent = String(128 + customScanCount);
    document.querySelector('#report-activity-count').textContent = String(128 + customScanCount);
    renderScanResult(host, result, mode);
    document.querySelector('#last-reviewed').textContent = 'just now';
}));

document.querySelectorAll('[data-message-mode]').forEach(button => button.addEventListener('click', () => {
    currentMessageMode = button.dataset.messageMode;
    document.querySelectorAll('[data-message-mode]').forEach(tab => {
        const active = tab === button;
        tab.classList.toggle('is-active', active);
        tab.setAttribute('aria-selected', String(active));
    });
    const form = document.querySelector('.message-scan-form');
    form.dataset.scanMode = currentMessageMode;
    document.querySelector('#message-input').placeholder = currentMessageMode === 'sms' ? 'Paste a suspicious text message here…' : 'Paste message text here. Include the sender line or link if relevant…';
    document.querySelector('#message-result').hidden = true;
}));

document.addEventListener('click', event => {
    const safeContinue = event.target.closest('[data-safe-continue]');
    if (safeContinue) showToast('No common warning signs were found. Continue carefully and verify the destination.');
    const scanAction = event.target.closest('[data-scan-action]');
    if (scanAction) {
        const action = scanAction.dataset.scanAction;
        const alert = alerts.find(item => item.id === currentScan?.alertId);
        if (alert) { alert.status = action[0].toUpperCase() + action.slice(1); renderAlerts(activeAlertFilter); }
        showToast(`${action[0].toUpperCase() + action.slice(1)} action recorded in this demo.`);
    }
    const alertAction = event.target.closest('[data-action-select]');
    if (alertAction) {
        const card = alertAction.closest('.alert-card');
        const alert = alerts.find(item => item.id === alertAction.dataset.alertAction);
        const action = card.querySelector('select').value;
        if (alert) { alert.status = action[0].toUpperCase() + action.slice(1); renderAlerts(activeAlertFilter); }
        showToast(`${action[0].toUpperCase() + action.slice(1)} action recorded in this demo.`);
    }
    const details = event.target.closest('[data-alert-details]');
    if (details) {
        const alert = alerts.find(item => item.id === details.dataset.alertDetails);
        if (alert) openAlertDetails(alert);
    }
    const appDetails = event.target.closest('[data-app-name]');
    if (appDetails) {
        const app = appInventory.find(item => item.name === appDetails.dataset.appName);
        if (app) openAlertDetails({ title: app.name, subject: app.source, source: app.publisher, time: 'Sample inventory', level: app.level, findings: [`Permission review: ${app.permissions}.`, `Install source: ${app.source}.`], recommendation: 'Confirm the app publisher and review requested permissions in your device settings.' });
    }
});

document.querySelectorAll('[data-alert-filter]').forEach(button => button.addEventListener('click', () => {
    document.querySelectorAll('[data-alert-filter]').forEach(filter => filter.classList.toggle('is-selected', filter === button));
    renderAlerts(button.dataset.alertFilter);
}));
document.querySelector('#mark-all-reviewed').addEventListener('click', () => {
    alerts.forEach(alert => { if (alert.status === 'New') alert.status = 'Reviewed'; });
    renderAlerts(activeAlertFilter);
    showToast('All new sample alerts marked as reviewed.');
});
document.querySelectorAll('[data-intel-filter]').forEach(button => button.addEventListener('click', () => {
    document.querySelectorAll('[data-intel-filter]').forEach(filter => filter.classList.toggle('is-selected', filter === button));
    renderIntel(button.dataset.intelFilter);
}));

document.querySelector('#brand-search-form').addEventListener('submit', event => {
    event.preventDefault();
    renderBrandResults(document.querySelector('#brand-input').value);
});
document.querySelectorAll('[data-range]').forEach(button => button.addEventListener('click', () => {
    document.querySelectorAll('[data-range]').forEach(range => range.classList.toggle('is-active', range === button));
    const days = Number(button.dataset.range);
    const values = days === 7 ? [22, 36, 28, 66, 42, 82, 57] : [22, 30, 18, 42, 34, 55, 24, 48, 37, 67, 50, 78, 42, 60];
    const labels = days === 7 ? ['M', 'T', 'W', 'T', 'F', 'S', 'S'] : ['1', '3', '5', '7', '9', '11', '13', '15', '17', '19', '21', '23', '25', '27'];
    renderTrendChart(document.querySelector('#report-chart'), values, labels);
}));

function downloadReport() {
    const quote = value => `"${String(value).replace(/"/g, '""')}"`;
    const rows = [['Alert', 'Subject', 'Source', 'Risk', 'Status', 'Time'], ...alerts.map(alert => [alert.title, alert.subject, alert.source, alert.level, alert.status, alert.time])];
    const csv = rows.map(row => row.map(quote).join(',')).join('\r\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
    const link = createElement('a');
    link.href = url;
    link.download = 'sentinel-demo-threat-report.csv';
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast('Demo report downloaded as a CSV file.');
}
document.querySelector('#export-report').addEventListener('click', downloadReport);

document.querySelectorAll('[data-setting-toggle]').forEach(toggle => toggle.addEventListener('click', () => {
    const enabled = toggle.getAttribute('aria-pressed') !== 'true';
    toggle.setAttribute('aria-pressed', String(enabled));
    toggle.classList.toggle('is-on', enabled);
    const setting = toggle.getAttribute('aria-label');
    if (setting === 'Toggle high-risk alerts') {
        preferences.highRiskAlerts = enabled;
        renderAlerts(activeAlertFilter);
    } else if (setting === 'Toggle sample advisories') {
        preferences.sampleAdvisories = enabled;
        renderIntel(activeIntelFilter);
    } else if (setting === 'Toggle reduced motion') {
        preferences.reducedMotion = enabled;
        document.body.classList.toggle('reduced-motion', enabled);
    }
}));
document.querySelector('#save-settings').addEventListener('click', () => {
    updateProfile(document.querySelector('#settings-name').value, document.querySelector('#settings-email').value);
    showToast('Preferences updated for this session.');
});
document.querySelector('#clear-session').addEventListener('click', () => {
    customScanCount = 0;
    document.querySelector('#activity-count').textContent = '128';
    document.querySelector('#report-activity-count').textContent = '128';
    document.querySelector('#url-result').hidden = true;
    document.querySelector('#message-result').hidden = true;
    alerts.splice(4);
    renderAlerts('all');
    showToast('Session scan history cleared. Sample alerts remain.');
});

const assistantPanel = document.querySelector('#assistant-panel');
document.querySelector('#assistant-open').addEventListener('click', () => { assistantPanel.hidden = false; document.querySelector('#assistant-input').focus(); });
document.querySelector('#assistant-close').addEventListener('click', () => { assistantPanel.hidden = true; });
document.querySelector('#assistant-form').addEventListener('submit', event => {
    event.preventDefault();
    const input = document.querySelector('#assistant-input');
    const question = input.value.trim();
    if (!question) return;
    const messages = document.querySelector('#assistant-messages');
    messages.append(createElement('div', 'assistant-message assistant-question', question));
    const latest = alerts[0];
    let answer;
    if (/latest|last alert|recent alert/i.test(question) && latest) {
        answer = `${latest.title} is marked ${latest.level}. ${latest.findings[0]} ${latest.recommendation}`;
    } else if (/score|risk level|low|medium|high/i.test(question) && currentScan) {
        answer = `This check scored ${currentScan.score} out of 100, which is ${currentScan.level} risk in this demo. ${currentScan.findings[0]} The score is a heuristic, not proof that something is safe or malicious.`;
    } else if (/safe|continue|open/i.test(question)) {
        answer = 'A low score only means these simple checks found few known warning signs. It cannot verify a site. Check the address carefully and use a trusted route if you are unsure.';
    } else {
        answer = latest ? `${latest.findings[0]} In plain language: pause before acting, and verify the sender or destination through a contact method you already trust. This is a local rule-based explanation.` : 'I can explain risk levels and common phishing signals. Paste a sample into a scanner first; sensitive messages should be redacted.';
    }
    messages.append(createElement('div', 'assistant-message assistant-response', answer));
    input.value = '';
    messages.scrollTop = messages.scrollHeight;
});

document.querySelector('#threat-dialog').addEventListener('click', event => {
    if (event.target === event.currentTarget) event.currentTarget.close();
});

renderOverviewAlerts();
renderSources();
renderTimeline();
renderIntel();
renderApps();
renderBrandResults('Northstar');
renderAlerts();
renderTrendChart(document.querySelector('#overview-chart'), [22, 36, 28, 66, 42, 82, 57], ['M', 'T', 'W', 'T', 'F', 'S', 'S']);
renderTrendChart(document.querySelector('#report-chart'), [22, 30, 18, 42, 34, 55, 24, 48, 37, 67, 50, 78, 42, 60], ['1', '3', '5', '7', '9', '11', '13', '15', '17', '19', '21', '23', '25', '27']);
document.querySelector('#topbar-title').textContent = 'Overview';
