'use strict';

const state = {
  token: sessionStorage.getItem('tv-token'),
  csrf: sessionStorage.getItem('tv-csrf'),
  user: null,
  documents: [],
  activeDocument: null,
  view: 'overview'
};
const $ = id => document.getElementById(id);
const ALLOWED_EXTENSIONS = new Set(['.pdf', '.txt', '.csv', '.png', '.jpg', '.jpeg', '.docx', '.xlsx']);
const MAX_FILE_SIZE = 10 * 1024 * 1024;

function notice(message, kind = 'info') {
  const node = $('notice');
  node.textContent = message;
  node.dataset.kind = kind;
  node.classList.add('show');
  clearTimeout(notice.timer);
  notice.timer = setTimeout(() => node.classList.remove('show'), 4500);
}

async function api(path, { method = 'GET', body, raw, headers = {} } = {}) {
  const requestHeaders = { ...headers };
  if (state.token) requestHeaders.Authorization = `Bearer ${state.token}`;
  if (body !== undefined) requestHeaders['Content-Type'] = 'application/json';
  if (['POST', 'PUT', 'DELETE'].includes(method) && state.csrf) requestHeaders['X-CSRF-Token'] = state.csrf;
  const response = await fetch(path, {
    method,
    headers: requestHeaders,
    body: body === undefined ? raw : JSON.stringify(body),
    cache: 'no-store'
  });
  if (!response.ok) {
    let result = {};
    try { result = await response.json(); } catch { /* Non-JSON error response. */ }
    if (response.status === 401 && state.token) expireSession();
    throw new Error(result.error || `Request failed (${response.status})`);
  }
  return response.headers.get('content-type')?.includes('application/json')
    ? response.json()
    : response.blob();
}

function field(form, name) {
  return new FormData(form).get(name)?.toString().trim() || '';
}
function rawField(form, name) {
  return new FormData(form).get(name)?.toString() || '';
}
function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}
function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? '—' : new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium', timeStyle: 'short'
  }).format(date);
}
function titleCase(value) {
  return String(value || '').replaceAll('_', ' ').replace(/\b\w/g, letter => letter.toUpperCase());
}
function roleLabel(role) {
  return ({ admin: 'Administrator', owner: 'Document owner', viewer: 'Viewer' })[role] || 'User';
}
function expireSession() {
  sessionStorage.clear();
  state.token = null;
  state.csrf = null;
  state.user = null;
  show();
  notice('Your session expired. Please sign in again.', 'warning');
}

function show() {
  const loggedIn = Boolean(state.token && state.user);
  $('login').hidden = loggedIn;
  $('workspace').hidden = !loggedIn;
  if (!loggedIn) return;

  const user = state.user;
  const initials = (user.username || 'U').slice(0, 1).toUpperCase();
  $('userAvatar').textContent = initials;
  $('userName').textContent = user.username;
  $('userRole').textContent = roleLabel(user.role);
  $('topIdentity').textContent = `${user.username} · ${roleLabel(user.role)}`;
  $('greetingName').textContent = user.username;
  $('settingsUsername').textContent = user.username;
  $('settingsRole').textContent = roleLabel(user.role);

  const isOwner = user.role === 'owner';
  $('overviewUpload').hidden = !isOwner;
  $('uploadButton').hidden = !isOwner;
  $('uploadPanel').hidden = !isOwner;
  $('activityNav').hidden = user.role !== 'admin';
  $('adminPanel').hidden = user.role !== 'admin';
  setView('overview');
  refreshDocuments();
  if (user.role === 'admin') loadAudit(true);
}

async function loadMe() {
  try {
    state.user = await api('/api/me');
    show();
  } catch {
    sessionStorage.clear();
    state.token = null;
    state.csrf = null;
    state.user = null;
    show();
  }
}

function setView(view) {
  if (view === 'activity' && state.user?.role !== 'admin') view = 'overview';
  state.view = view;
  for (const section of document.querySelectorAll('.view-section')) {
    section.hidden = section.id !== `${view}View`;
  }
  for (const button of document.querySelectorAll('.nav-item[data-view]')) {
    button.classList.toggle('active', button.dataset.view === view);
  }
  const labels = { overview: 'Overview', documents: 'All documents', shared: 'Shared with me', activity: 'Audit activity', settings: 'Account settings' };
  $('pageCrumb').textContent = labels[view] || 'Overview';
  if (view === 'documents' || view === 'shared') refreshDocuments();
  if (view === 'activity') loadAudit(false);
}

function currentFilters() {
  const query = new URLSearchParams(new FormData($('searchForm')));
  return query.toString();
}

async function refreshDocuments() {
  if (!state.user) return;
  try {
    const query = currentFilters();
    state.documents = await api(`/api/documents${query ? `?${query}` : ''}`);
    renderDocuments();
  } catch (error) {
    if (state.token) notice(error.message, 'error');
  }
}

function documentIcon(name) {
  const extension = name.split('.').pop()?.toLowerCase() || 'file';
  return extension.slice(0, 4).toUpperCase();
}

function actionButton(label, className, handler, title = label) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = className;
  button.textContent = label;
  button.title = title;
  button.addEventListener('click', handler);
  return button;
}

function makeDocumentRow(doc, compact = false) {
  const row = document.createElement(compact ? 'article' : 'tr');
  row.className = compact ? 'document-card' : '';
  const name = escapeHTML(doc.name);
  const owner = escapeHTML(doc.owner);
  const category = escapeHTML(doc.category);
  const access = doc.permission === 'owner' ? 'Owner' : titleCase(doc.permission);
  const accessClass = doc.permission === 'owner' ? 'owner' : doc.permission === 'edit' ? 'edit' : 'read';
  const nameCell = `<div class="file-cell"><span class="file-type">${escapeHTML(documentIcon(doc.name))}</span><span class="file-description"><strong>${name}</strong><small>${formatBytes(Number(doc.size) || 0)} · ${escapeHTML(doc.mime || 'Document')}</small></span></div>`;
  const controls = document.createElement('div');
  controls.className = 'row-actions';
  controls.append(actionButton('Download', 'mini-action', () => downloadDocument(doc), `Download ${doc.name}`));
  if (doc.permission === 'owner') {
    controls.append(actionButton('Share', 'mini-action', () => openShare(doc)));
    controls.append(actionButton('Access', 'mini-action', () => openPermissions(doc)));
    controls.append(actionButton('Edit', 'mini-action', () => openEdit(doc)));
    controls.append(actionButton('Delete', 'mini-action danger-text', () => deleteDocument(doc)));
  } else if (doc.permission === 'edit') {
    controls.append(actionButton('Edit', 'mini-action', () => openEdit(doc)));
    controls.append(actionButton('Replace', 'mini-action', () => replaceDocument(doc)));
  }
  if (compact) {
    row.innerHTML = `<div class="compact-doc-main">${nameCell}<span class="access-badge ${accessClass}">${access}</span></div><div class="compact-doc-meta"><span>${owner}</span><span>${category}</span><span>${formatDate(doc.updated_at || doc.created_at)}</span></div>`;
  } else {
    row.innerHTML = `<td>${nameCell}</td><td>${owner}</td><td><span class="category-chip">${category}</span></td><td>${formatDate(doc.updated_at || doc.created_at)}</td><td><span class="access-badge ${accessClass}">${access}</span></td><td class="actions-cell"></td>`;
    row.querySelector('.actions-cell').append(controls);
  }
  if (compact) row.append(controls);
  return row;
}

function renderDocuments() {
  const all = state.documents;
  const visible = state.view === 'shared' ? all.filter(doc => doc.permission !== 'owner') : all;
  $('navDocCount').textContent = String(all.length);
  $('statAccessible').textContent = String(all.length);
  $('statOwned').textContent = String(all.filter(doc => doc.permission === 'owner').length);
  $('statShared').textContent = String(all.filter(doc => doc.permission !== 'owner').length);

  const table = $('documents');
  table.replaceChildren();
  const empty = $('emptyDocuments');
  const tableWrap = document.querySelector('.table-wrap');
  const rows = state.view === 'shared' ? visible : all;
  for (const doc of rows) table.append(makeDocumentRow(doc));
  empty.hidden = rows.length > 0;
  tableWrap.hidden = rows.length === 0;
  if (rows.length === 0) {
    const title = empty.querySelector('h3');
    const paragraph = empty.querySelector('p');
    if (state.view === 'shared') {
      title.textContent = 'Nothing has been shared with you yet';
      paragraph.textContent = 'When an owner grants you access, those documents will appear here.';
    } else {
      title.textContent = 'No documents found';
      paragraph.textContent = 'Try changing your search or ask an owner to share a document with you.';
    }
  }
  const recent = $('recentDocuments');
  recent.replaceChildren();
  const recentDocs = [...all].sort((a, b) => String(b.updated_at || b.created_at).localeCompare(String(a.updated_at || a.created_at))).slice(0, 5);
  if (recentDocs.length) {
    for (const doc of recentDocs) recent.append(makeDocumentRow(doc, true));
  } else {
    const message = document.createElement('div');
    message.className = 'empty-inline';
    message.textContent = 'No documents are available to your account yet.';
    recent.append(message);
  }
}

async function downloadDocument(doc) {
  try {
    const blob = await api(`/api/documents/${encodeURIComponent(doc.id)}/content`);
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = doc.name;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    notice(error.message, 'error');
  }
}

async function replaceDocument(doc) {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = [...ALLOWED_EXTENSIONS].join(',');
  input.addEventListener('change', async () => {
    const file = input.files?.[0];
    if (!file) return;
    if (file.size > MAX_FILE_SIZE) return notice('The maximum file size is 10 MiB.', 'warning');
    const extension = `.${file.name.split('.').pop()}`.toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(extension)) return notice('Choose a PDF, TXT, CSV, PNG, JPG, DOCX or XLSX file.', 'warning');
    try {
      await api(`/api/documents/${encodeURIComponent(doc.id)}/content`, {
        method: 'PUT', raw: await file.arrayBuffer(), headers: { 'Content-Type': 'application/octet-stream' }
      });
      notice('Document replaced successfully.', 'success');
      await refreshDocuments();
    } catch (error) { notice(error.message, 'error'); }
  });
  input.click();
}

function openUpload() {
  setView('documents');
  $('uploadPanel').hidden = state.user?.role !== 'owner';
  $('uploadPanel').scrollIntoView({ behavior: 'smooth', block: 'center' });
  $('uploadForm').elements.file.focus({ preventScroll: true });
}

async function openShare(doc) {
  try {
    const users = await api('/api/users');
    const select = $('shareUser');
    select.replaceChildren();
    for (const user of users.filter(person => person.id !== state.user.id)) {
      const option = document.createElement('option');
      option.value = user.id;
      option.textContent = `${user.username} · ${roleLabel(user.role)}`;
      select.append(option);
    }
    if (!select.options.length) return notice('There are no other active accounts to share with.', 'warning');
    state.activeDocument = doc;
    $('shareDocumentName').textContent = doc.name;
    $('sharePermission').value = 'read';
    $('shareDialog').showModal();
  } catch (error) { notice(error.message, 'error'); }
}

async function openPermissions(doc) {
  try {
    state.activeDocument = doc;
    $('permissionsDocumentName').textContent = doc.name;
    const grants = await api(`/api/documents/${encodeURIComponent(doc.id)}/permissions`);
    const list = $('grantList');
    list.replaceChildren();
    if (!grants.length) {
      const empty = document.createElement('p');
      empty.className = 'empty-inline';
      empty.textContent = 'No one else currently has access to this document.';
      list.append(empty);
    }
    for (const grant of grants) {
      const row = document.createElement('div');
      row.className = 'grant-row';
      const identity = document.createElement('div');
      identity.innerHTML = `<strong>${escapeHTML(grant.username)}</strong><small>${titleCase(grant.permission)} access · granted ${formatDate(grant.granted_at)}</small>`;
      const revoke = actionButton('Revoke', 'mini-action danger-text', async () => {
        try {
          await api(`/api/documents/${encodeURIComponent(doc.id)}/permissions`, { method: 'DELETE', body: { user_id: grant.user_id } });
          notice('Access revoked. The change applies on the next request.', 'success');
          await openPermissions(doc);
          await refreshDocuments();
        } catch (error) { notice(error.message, 'error'); }
      });
      row.append(identity, revoke);
      list.append(row);
    }
    if (!$('permissionsDialog').open) $('permissionsDialog').showModal();
  } catch (error) { notice(error.message, 'error'); }
}

function openEdit(doc) {
  state.activeDocument = doc;
  $('editName').value = doc.name;
  $('editCategory').value = doc.category;
  $('editDialog').showModal();
}

async function deleteDocument(doc) {
  if (!window.confirm(`Delete "${doc.name}" from the library? Its grants will be removed.`)) return;
  try {
    await api(`/api/documents/${encodeURIComponent(doc.id)}`, { method: 'DELETE' });
    notice('Document deleted and all grants removed.', 'success');
    await refreshDocuments();
  } catch (error) { notice(error.message, 'error'); }
}

function renderAuditRows(target, events) {
  target.replaceChildren();
  if (!events.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-inline';
    empty.textContent = 'No activity has been recorded yet.';
    target.append(empty);
    return;
  }
  for (const event of events) {
    const row = document.createElement('article');
    row.className = 'activity-row';
    const outcomeClass = event.outcome === 'allowed' ? 'allowed' : 'denied';
    row.innerHTML = `<span class="activity-mark ${outcomeClass}">${event.outcome === 'allowed' ? '✓' : '!'}</span><div class="activity-copy"><strong>${escapeHTML(titleCase(event.action))}${event.document_name ? ` · ${escapeHTML(event.document_name)}` : ''}</strong><small>${escapeHTML(event.actor_name || 'Anonymous')} · ${formatDate(event.at)} · #${Number(event.seq) || 0}</small><p>${escapeHTML(event.detail || '')}</p></div><span class="outcome-badge ${outcomeClass}">${escapeHTML(titleCase(event.outcome))}</span>`;
    target.append(row);
  }
}

async function loadAudit(preview) {
  if (state.user?.role !== 'admin') return;
  try {
    const events = await api('/api/admin/activity?limit=100');
    if (preview) renderAuditRows($('auditPreview'), events.slice(0, 5));
    else renderAuditRows($('auditFull'), events);
  } catch (error) { notice(error.message, 'error'); }
}

async function verifyAudit() {
  try {
    const result = await api('/api/admin/audit/verify');
    notice(result.valid ? `Audit chain verified · ${result.entries} events` : `Audit chain check failed at event ${result.broken_at_seq}`, result.valid ? 'success' : 'error');
  } catch (error) { notice(error.message, 'error'); }
}

$('loginForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.submitter || event.target.querySelector('button[type="submit"],button:not([type])');
  if (button) button.disabled = true;
  try {
    const result = await api('/api/login', {
      method: 'POST', body: { username: field(event.target, 'username'), password: rawField(event.target, 'password') }
    });
    state.token = result.token;
    state.csrf = result.csrf;
    state.user = result.user;
    sessionStorage.setItem('tv-token', state.token);
    sessionStorage.setItem('tv-csrf', state.csrf);
    show();
  } catch (error) { notice(error.message, 'error'); }
  finally { if (button) button.disabled = false; }
});

async function logout() {
  try { await api('/api/logout', { method: 'POST' }); } catch { /* Local session is cleared even when the network is unavailable. */ }
  sessionStorage.clear();
  state.token = null;
  state.csrf = null;
  state.user = null;
  state.documents = [];
  show();
}
$('logout').addEventListener('click', logout);
$('topLogout').addEventListener('click', logout);

$('passwordForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.target;
  const next = rawField(form, 'new_password');
  if (next !== rawField(form, 'confirm_password')) return notice('New passwords do not match.', 'warning');
  try {
    const result = await api('/api/password', {
      method: 'POST', body: { current_password: rawField(form, 'current_password'), new_password: next }
    });
    form.reset();
    sessionStorage.clear();
    state.token = null;
    state.csrf = null;
    state.user = null;
    show();
    showRecovery(result.recovery_code, 'Password updated. Save your new recovery code, then sign in again.');
  } catch (error) { notice(error.message, 'error'); }
});

$('uploadForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.target;
  const file = form.elements.file.files[0];
  if (!file) return notice('Choose a file to upload.', 'warning');
  if (file.size > MAX_FILE_SIZE) return notice('The maximum file size is 10 MiB.', 'warning');
  if (!ALLOWED_EXTENSIONS.has(`.${file.name.split('.').pop()}`.toLowerCase())) return notice('Choose a PDF, TXT, CSV, PNG, JPG, DOCX or XLSX file.', 'warning');
  const submit = form.querySelector('button[type="submit"],button:not([type])');
  if (submit) { submit.disabled = true; submit.textContent = 'Uploading securely…'; }
  try {
    const result = await api('/api/documents', {
      method: 'POST', raw: await file.arrayBuffer(),
      headers: { 'X-File-Name': file.name, 'X-Category': field(form, 'category'), 'Content-Type': 'application/octet-stream' }
    });
    notice(`Uploaded ${result.name}.`, 'success');
    form.reset();
    $('fileHint').textContent = 'PDF, TXT, CSV, PNG, JPG, DOCX or XLSX · up to 10 MiB';
    await refreshDocuments();
  } catch (error) { notice(error.message, 'error'); }
  finally { if (submit) { submit.disabled = false; submit.textContent = 'Upload securely'; } }
});

$('searchForm').addEventListener('submit', event => { event.preventDefault(); refreshDocuments(); });
$('clearFilters').addEventListener('click', () => { $('searchForm').reset(); refreshDocuments(); });
$('verify').addEventListener('click', verifyAudit);
$('verifyActivity').addEventListener('click', verifyAudit);
$('overviewUpload').addEventListener('click', openUpload);
$('uploadButton').addEventListener('click', openUpload);
$('uploadForm').elements.file.addEventListener('change', event => {
  const file = event.target.files?.[0];
  $('fileHint').textContent = file ? `${file.name} · ${formatBytes(file.size)}` : 'PDF, TXT, CSV, PNG, JPG, DOCX or XLSX · up to 10 MiB';
});
for (const button of document.querySelectorAll('.nav-item[data-view]')) button.addEventListener('click', () => setView(button.dataset.view));
for (const button of document.querySelectorAll('[data-goto]')) button.addEventListener('click', () => setView(button.dataset.goto));
for (const button of document.querySelectorAll('[data-close]')) button.addEventListener('click', () => $(button.dataset.close).close());
for (const dialog of document.querySelectorAll('dialog')) dialog.addEventListener('click', event => {
  if (event.target === dialog) dialog.close();
});
$('shareForm').addEventListener('submit', async event => {
  event.preventDefault();
  if (!state.activeDocument) return;
  try {
    await api(`/api/documents/${encodeURIComponent(state.activeDocument.id)}/permissions`, {
      method: 'POST', body: { user_id: $('shareUser').value, permission: $('sharePermission').value }
    });
    $('shareDialog').close();
    notice('Access granted.', 'success');
    await refreshDocuments();
  } catch (error) { notice(error.message, 'error'); }
});
$('editForm').addEventListener('submit', async event => {
  event.preventDefault();
  if (!state.activeDocument) return;
  try {
    await api(`/api/documents/${encodeURIComponent(state.activeDocument.id)}`, {
      method: 'PUT', body: { name: $('editName').value.trim(), category: $('editCategory').value.trim() }
    });
    $('editDialog').close();
    notice('Document details updated.', 'success');
    await refreshDocuments();
  } catch (error) { notice(error.message, 'error'); }
});

function authMode(mode) {
  $('loginForm').hidden = mode !== 'login';
  $('registerForm').hidden = mode !== 'register';
  $('resetForm').hidden = mode !== 'reset';
  $('authLinks').hidden = mode !== 'login';
  $('recoveryBox').hidden = true;
}
function showRecovery(code, heading) {
  $('recoveryTitle').textContent = heading;
  $('recoveryCode').textContent = code;
  $('recoverySaved').checked = false;
  $('continueToLogin').disabled = true;
  authMode('recovery');
  $('recoveryBox').hidden = false;
}
$('showRegister').addEventListener('click', () => authMode('register'));
$('showReset').addEventListener('click', () => authMode('reset'));
$('backToLoginFromRegister').addEventListener('click', () => authMode('login'));
$('backToLoginFromReset').addEventListener('click', () => authMode('login'));
$('recoverySaved').addEventListener('change', event => { $('continueToLogin').disabled = !event.target.checked; });
$('continueToLogin').addEventListener('click', () => { authMode('login'); notice('You can now sign in.', 'success'); });
$('copyRecovery').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('recoveryCode').textContent); notice('Recovery code copied.', 'success'); }
  catch { notice('Select and copy the recovery code shown above.', 'warning'); }
});
$('registerForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.target;
  const password = rawField(form, 'password');
  if (password !== rawField(form, 'confirm_password')) return notice('Passwords do not match.', 'warning');
  try {
    const result = await api('/api/register', { method: 'POST', body: { username: field(form, 'username'), password } });
    form.reset();
    showRecovery(result.recovery_code, 'Account created. Save your recovery code before signing in.');
  } catch (error) { notice(error.message, 'error'); }
});
$('resetForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.target;
  const password = rawField(form, 'new_password');
  if (password !== rawField(form, 'confirm_password')) return notice('Passwords do not match.', 'warning');
  try {
    const result = await api('/api/password/reset', {
      method: 'POST', body: { username: field(form, 'username'), recovery_code: rawField(form, 'recovery_code'), new_password: password }
    });
    form.reset();
    showRecovery(result.recovery_code, 'Password reset. Save your replacement recovery code, then sign in.');
  } catch (error) { notice(error.message, 'error'); }
});

if (state.token) loadMe();
