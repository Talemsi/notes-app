'use strict';
(function () {

/* ── Crypto ── */
const LS_SALT      = 'ns_salt_v3';   // legacy (migration only)
const LS_DATA      = 'ns_data_v4';   // legacy (migration only)
const LS_USERS      = 'ns_users_v1';
const groqKey = () => `ns_gk_${currentUserId}`;
const LOCK_TIMEOUT    = 5 * 60 * 1000;
const MAX_ATT         = 5;
const BLOCK_MS        = 2 * 60 * 1000;
const DEVICE_USER_KEY = 'ns_dv';

/* Vault params for new vaults — 600k iterations + SHA-512 (OWASP 2024) */
const NEW_VAULT_PARAMS = { iter: 600_000, hash: 'SHA-512' };
/* Legacy default for vaults created before this version */
const LEGACY_PARAMS    = { iter: 100_000, hash: 'SHA-256' };

const saltKey       = id => `ns_s3_${id}`;
const dataKey       = id => `ns_d4_${id}`;
const blockKey      = id => `ns_bl_${id}`;
const failsKey      = id => `ns_fa_${id}`;
const vaultParamsKey= id => `ns_vp_${id}`;
const metaKey       = id => `ns_mt_${id}`;

/* ── Security Audit Log (in-memory, cleared on lock) ── */
const _secLog = [];
function secAudit(event, detail = '') {
    _secLog.push({ ts: new Date().toISOString(), ev: event, d: String(detail).slice(0, 120) });
    if (_secLog.length > 500) _secLog.shift();
}

/* ── Input Validation ── */
function validateStr(v, maxLen, label) {
    if (typeof v !== 'string') throw new Error('Entrée invalide');
    if (v.length > maxLen) throw new Error(`${label} trop long (max ${maxLen} caractères)`);
    return v.trim();
}

/* ── Lock screen — rotating text, app window animation & personal stats ── */
const PV_WORDS = ['vos idées.', 'vos projets.', 'vos connaissances.', 'tout, sécurisé.'];
let _pvIdx = 0, _pvTimer = null;
function startPvRotate() {
    const el = document.getElementById('pvRotate');
    if (!el) return;
    clearInterval(_pvTimer);
    _pvTimer = setInterval(() => {
        _pvIdx = (_pvIdx + 1) % PV_WORDS.length;
        el.style.transform = `translateY(-${_pvIdx * 40}px)`;
    }, 3000);
}

let _awTimer = null, _awItemIdx = 0, _awCatIdx = 0;
const AW_ITEMS = 6, AW_CATS = 6;
const AW_CAT_SEQ = [0, 1, 0, 2, 0, 3, 0, 4, 0, 1];
function startAwAnimation() {
    clearInterval(_awTimer);
    _awItemIdx = 0; _awCatIdx = 0;
    _awTimer = setInterval(() => {
        const prevItem = document.getElementById(`awItem${_awItemIdx}`);
        const prevCat  = document.getElementById(`awCat${AW_CAT_SEQ[_awCatIdx]}`);
        if (prevItem) prevItem.classList.remove('on');
        if (prevCat)  prevCat.classList.remove('on');
        _awItemIdx = (_awItemIdx + 1) % AW_ITEMS;
        _awCatIdx  = (_awCatIdx  + 1) % AW_CAT_SEQ.length;
        const nextItem = document.getElementById(`awItem${_awItemIdx}`);
        const nextCat  = document.getElementById(`awCat${AW_CAT_SEQ[_awCatIdx]}`);
        if (nextItem) nextItem.classList.add('on');
        if (nextCat)  nextCat.classList.add('on');
    }, 2200);
}

function saveUserMeta() {
    if (!currentUserId) return;
    const n_ = _vault.getNotes();
    const cats = new Set(n_.map(n => n.category).filter(Boolean));
    localStorage.setItem(metaKey(currentUserId), JSON.stringify({
        lastLogin: new Date().toISOString(),
        noteCount: n_.length,
        catCount:  cats.size
    }));
}

function showUserMeta(id) {
    const pvStats = document.getElementById('pvStats');
    if (!pvStats) return;
    try {
        const m = JSON.parse(localStorage.getItem(metaKey(id)) || 'null');
        if (!m) { pvStats.style.display = 'none'; return; }
        document.getElementById('pvNoteCount').textContent = m.noteCount ?? '—';
        document.getElementById('pvCatCount').textContent  = m.catCount  ?? '—';
        if (m.lastLogin) {
            const d = new Date(m.lastLogin);
            const now = new Date();
            const time = d.toLocaleTimeString('fr-FR', {hour:'2-digit', minute:'2-digit'});
            const isToday = d.toDateString() === now.toDateString();
            const isYest  = d.toDateString() === new Date(now - 86400000).toDateString();
            document.getElementById('pvLastLogin').textContent =
                isToday ? `Aujourd'hui à ${time}` : isYest ? `Hier à ${time}` : `il y a ${Math.floor((Date.now()-d)/86400000)}j`;
        }
        pvStats.style.display = 'flex';
    } catch { pvStats.style.display = 'none'; }
}

function getUsers() { try { return JSON.parse(localStorage.getItem(LS_USERS) || '[]'); } catch { return []; } }
function saveUsers(u) { localStorage.setItem(LS_USERS, JSON.stringify(u)); }

function migrate() {
    const oldSalt = localStorage.getItem(LS_SALT);
    if (!oldSalt) return;
    const users = getUsers();
    if (users.find(u => u.id === '_v1')) return;
    const id = '_v1';
    localStorage.setItem(saltKey(id), oldSalt);
    const d = localStorage.getItem(LS_DATA) || localStorage.getItem('ns_data_v3');
    if (d) localStorage.setItem(dataKey(id), d);
    users.unshift({ id, name: 'Mes notes' });
    saveUsers(users);
    ['ns_salt_v3','ns_data_v4','ns_data_v3','ns_block_v1','notes','ns_name'].forEach(k => localStorage.removeItem(k));
    sessionStorage.removeItem('ns_fails_v1');
}

/* Clé, notes et rendez-vous isolés dans une closure — inaccessibles via window.* ou console */
const _vault = (() => {
    let _k     = null;
    let _notes = [];
    let _appts = [];
    return {
        /* Clé */
        setKey(k)        { _k = k; },
        getKey()         { return _k; },
        isOpen()         { return _k !== null; },
        /* Notes */
        getNotes()       { return _notes; },
        setNotes(n)      { _notes = Array.isArray(n) ? n : []; },
        addNote(n)       { _notes.push(n); },
        filterNotes(fn)  { _notes = _notes.filter(fn); },
        /* Rendez-vous */
        getAppts()       { return _appts; },
        setAppts(a)      { _appts = Array.isArray(a) ? a : []; },
        addAppt(a)       { _appts.push(a); },
        filterAppts(fn)  { _appts = _appts.filter(fn); },
        /* Verrouillage — purge complète avec écrasement avant libération GC */
        lock() {
            _k = null;
            _notes.fill(null); _notes.length = 0;
            _appts.fill(null); _appts.length = 0;
        }
    };
})();
let lockTimer;
let fails = 0, blockedUntil = 0;
let state = 'unlock', tmpPwd = null;
let currentUserId = null;

const enc    = t => new TextEncoder().encode(t);
const dec    = b => new TextDecoder().decode(b);
function toB64(buf) {
    const bytes = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
}
const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function deriveKey(pw, salt, params = LEGACY_PARAMS) {
    const raw = await crypto.subtle.importKey('raw', enc(pw), { name:'PBKDF2' }, false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name:'PBKDF2', salt, iterations: params.iter, hash: params.hash },
        raw, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']
    );
}
async function cryptEnc(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, enc(JSON.stringify(data)));
    const out = new Uint8Array(12 + ct.byteLength);
    out.set(iv); out.set(new Uint8Array(ct), 12);
    return toB64(out);
}
async function cryptDec(b64, key) {
    const buf = fromB64(b64);
    const pt  = await crypto.subtle.decrypt({ name:'AES-GCM', iv:buf.slice(0,12) }, key, buf.slice(12));
    return JSON.parse(dec(pt));
}
async function tryUnlock(pw) {
    const sb = localStorage.getItem(saltKey(currentUserId));
    if (!sb) return null;
    try {
        let params = LEGACY_PARAMS;
        try {
            const vp = JSON.parse(localStorage.getItem(vaultParamsKey(currentUserId)) || 'null');
            if (vp?.iter && vp?.hash) params = vp;
        } catch {}
        const key = await deriveKey(pw, fromB64(sb), params);
        const blob = localStorage.getItem(dataKey(currentUserId));
        if (!blob) return { key, notes: [], appointments: [] };
        const raw = await cryptDec(blob, key);
        if (Array.isArray(raw)) return { key, notes: raw, appointments: [] };
        return { key, notes: raw.notes || [], appointments: raw.appointments || [] };
    } catch { return null; }
}
async function createVault(pw) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    localStorage.setItem(saltKey(currentUserId), toB64(salt));
    localStorage.setItem(vaultParamsKey(currentUserId), JSON.stringify(NEW_VAULT_PARAMS));
    const key = await deriveKey(pw, salt, NEW_VAULT_PARAMS);
    localStorage.setItem(dataKey(currentUserId), await cryptEnc({ notes: [], appointments: [] }, key));
    return key;
}
async function reencrypt(pw) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    localStorage.setItem(saltKey(currentUserId), toB64(salt));
    localStorage.setItem(vaultParamsKey(currentUserId), JSON.stringify(NEW_VAULT_PARAMS));
    _vault.setKey(await deriveKey(pw, salt, NEW_VAULT_PARAMS));
    localStorage.setItem(dataKey(currentUserId), await cryptEnc({ notes: _vault.getNotes(), appointments: _vault.getAppts() }, _vault.getKey()));
}
async function persist() {
    if (!_vault.isOpen() || !currentUserId) return;
    localStorage.setItem(dataKey(currentUserId), await cryptEnc({ notes: _vault.getNotes(), appointments: _vault.getAppts() }, _vault.getKey()));
}

/* ── Lock screen ── */
const $ = id => document.getElementById(id);
const esc = t => { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; };

function ui({ icon='fa-lock', title='Notes', hint='', btn='Continuer', err='', att='',
              showChange=false, showBack=false, pwMode=true, placeholder='' }) {
    $('lockIconEl').className        = `fas ${icon}`;
    $('lockTitle').textContent       = title;
    $('lockHint').textContent        = hint;
    $('lockBtn').textContent         = btn;
    $('lockErr').textContent         = err;
    $('lockAtt').textContent         = att;
    $('changePwdLink').style.display = showChange ? 'inline' : 'none';
    $('backLink').style.display      = showBack   ? 'inline' : 'none';
    $('lockInput').type              = pwMode ? 'password' : 'text';
    $('lockInput').className         = pwMode ? 'pw' : '';
    $('lockInput').placeholder       = placeholder;
    $('lockInput').value             = '';
    $('lockBtn').disabled            = false;
    $('lockInput').disabled          = false;
    $('lockEye').classList.toggle('on', pwMode);
    $('eyeIco').className            = 'fas fa-eye';
    $('userGrid').style.display      = 'none';
    $('lockField').style.display     = '';
    $('lockBtn').style.display       = '';
    setTimeout(() => $('lockInput').focus(), 50);
}

function showSelectUser() {
    state = 'select';
    currentUserId = null;
    fails = 0; blockedUntil = 0;
    const pvStats = document.getElementById('pvStats');
    if (pvStats) pvStats.style.display = 'none';
    const users = getUsers();

    $('lockIconEl').className        = 'fas fa-lock';
    $('lockTitle').textContent       = 'Notes';
    $('lockErr').textContent         = '';
    $('lockAtt').textContent         = '';
    $('lockHint').textContent        = users.length === 0 ? 'Créez votre premier profil.' : '';
    $('changePwdLink').style.display = 'none';
    $('backLink').style.display      = 'none';
    $('lockField').style.display     = 'none';
    $('lockBtn').style.display       = 'none';
    $('userGrid').style.display      = 'grid';

    $('userGrid').innerHTML = users.map(u =>
        `<div class="user-card" data-userid="${esc(u.id)}">
            <div class="user-av">${esc(u.name.charAt(0).toUpperCase())}</div>
            <div class="user-nm">${esc(u.name)}</div>
            <button class="user-del" data-useridel="${esc(u.id)}" title="Supprimer">×</button>
        </div>`
    ).join('') +
        `<div class="user-card" data-new-user="1">
            <div class="user-av user-av-new"><i class="fas fa-plus"></i></div>
            <div class="user-nm user-nm-new">Nouveau</div>
        </div>`;
}

function selectUser(id) {
    const user = getUsers().find(u => u.id === id);
    if (!user) return;
    currentUserId = id;
    fails        = parseInt(sessionStorage.getItem(failsKey(id)) || '0', 10);
    blockedUntil = parseInt(localStorage.getItem(blockKey(id))   || '0', 10);
    showUserMeta(id);

    if (!localStorage.getItem(saltKey(id))) {
        state = 'setup_1';
        ui({ title: user.name, hint: 'Choisissez un mot de passe (min. 8 caractères).', btn: 'Continuer', showBack: true });
    } else {
        state = 'unlock';
        ui({ title: user.name, btn: 'Déverrouiller', showChange: true, showBack: true });
    }
}

function startNewUser() {
    state = 'setup_name';
    ui({ hint: 'Choisissez un nom pour ce profil.', btn: 'Continuer', showBack: true, pwMode: false, placeholder: 'Marouane...' });
}

async function deleteUser(id) {
    const user = getUsers().find(u => u.id === id);
    if (!user || !confirm(`Supprimer le profil « ${user.name} » et toutes ses notes ?`)) return;
    saveUsers(getUsers().filter(u => u.id !== id));
    [saltKey(id), dataKey(id), blockKey(id), vaultParamsKey(id), metaKey(id), `ns_ck_${id}`, `ns_ok_${id}`, `ns_gk_${id}`].forEach(k => localStorage.removeItem(k));
    sessionStorage.removeItem(failsKey(id));
    if (localStorage.getItem(DEVICE_USER_KEY) === id) localStorage.removeItem(DEVICE_USER_KEY);
    showSelectUser();
}

function showLock() {
    $('lockScreen').classList.add('show');
    $('appContent').classList.remove('show');
    clearTimeout(lockTimer);
    startPvRotate();
    startAwAnimation();
    migrate();
    const storedId = localStorage.getItem(DEVICE_USER_KEY);
    const known    = storedId && getUsers().find(u => u.id === storedId);
    if (known) selectUser(storedId); else showSelectUser();
}

function updateSidebar() {
    const user = getUsers().find(u => u.id === currentUserId);
    if (user) {
        $('sbAvatar').textContent = user.name.charAt(0).toUpperCase();
        $('sbUname').textContent  = user.name;
    }
    const allNotes = _vault.getNotes();
    const active = allNotes.filter(n => !n.closed);
    const closed = allNotes.filter(n => n.closed);
    $('sbAllCt').textContent = active.length;
    const closedPill = $('sbClosedCt');
    if (closed.length) { closedPill.textContent = closed.length; closedPill.style.display = ''; }
    else { closedPill.style.display = 'none'; }
    const today = new Date().toISOString().split('T')[0];
    const upcomingAppts = _vault.getAppts().filter(a => a.date >= today);
    const calPill = $('sbCalCt');
    if (upcomingAppts.length) { calPill.textContent = upcomingAppts.length; calPill.style.display = ''; }
    else { calPill.style.display = 'none'; }
    const cats = [...new Set(active.map(n => n.category).filter(Boolean))].sort();
    $('sbCats').innerHTML = cats.map(c => {
        const ct = active.filter(n => n.category === c).length;
        return `<div class="sb-item" data-cat="${esc(c)}">
            <i class="fas fa-tag"></i> ${esc(c)}
            <span class="sb-cat-pill">${ct}</span>
        </div>`;
    }).join('');
}

let sbCurrentFilter = null;
function showWorkspace(isCalendar) {
    $('workspace') && ($('workspace').style.display = isCalendar ? 'none' : '');
    const cv = $('calView');
    if (isCalendar) { cv.classList.add('show'); }
    else            { cv.classList.remove('show'); }
}

function sbFilter(filter, el) {
    sbCurrentFilter = filter;
    _closedFilter = (filter === 'closed');
    document.querySelectorAll('.sb-item').forEach(i => i.classList.remove('active'));
    if (el) el.classList.add('active');
    if (filter === 'calendar') {
        showWorkspace(true);
        renderCalendar();
        return;
    }
    showWorkspace(false);
    if (!filter || filter === 'recent') {
        render('', filter === 'recent' ? 5 : null);
    } else if (filter === 'closed') {
        render('');
    } else if (filter.startsWith('cat:')) {
        const cat = filter.slice(4);
        render('', null, cat);
    }
}

function showApp() {
    secAudit('LOGIN', currentUserId);
    localStorage.setItem(DEVICE_USER_KEY, currentUserId);
    $('lockScreen').classList.remove('show');
    $('appContent').classList.add('show');
    $('fDate').min = new Date().toISOString().split('T')[0];
    resetTimer();
    render();
    checkRem();
    updateSidebar();
}

function lockApp() {
    secAudit('LOCK', currentUserId || '');
    saveUserMeta();
    /* Zeroize sensitive in-memory state */
    _vault.lock(); tmpPwd = null; currentUserId = null;
    _secLog.length = 0;
    clearTimeout(lockTimer);
    $('nlist').innerHTML = '';
    selectMode = false; selected.clear();
    $('bulkBar').classList.remove('show');
    $('ribbon').classList.remove('show');
    if ($('searchIn')) { $('searchIn').value = ''; $('searchCt').textContent = ''; }
    $('searchClr')?.classList.remove('on');
    /* Clear any sensitive form fields */
    if ($('cfgKey')) $('cfgKey').value = '';
    closeNote(); closeRem(); closeCompiler();
    showLock();
}

function resetTimer() {
    clearTimeout(lockTimer);
    lockTimer = setTimeout(lockApp, LOCK_TIMEOUT);
}

function setBusy(on) {
    $('lockBtn').disabled   = on;
    $('lockInput').disabled = on;
    if (on) $('lockBtn').textContent = '…';
}

async function handleLock() {
    if (Date.now() < blockedUntil) {
        $('lockErr').textContent = `Trop de tentatives — réessayez dans ${Math.ceil((blockedUntil-Date.now())/1000)} s.`;
        return;
    }
    const v = $('lockInput').value;
    if (!v.trim()) { $('lockErr').textContent = 'Champ requis.'; return; }
    setBusy(true);
    try { await dispatch(v); } finally { setBusy(false); }
}

async function dispatch(v) {
    switch (state) {
        case 'setup_name': {
            const name = v.trim();
            if (!name) { $('lockErr').textContent = 'Choisissez un nom.'; return; }
            if (name.length > 30) { $('lockErr').textContent = 'Nom trop long (max 30 caractères).'; return; }
            const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
            const users = getUsers();
            users.push({ id, name });
            saveUsers(users);
            currentUserId = id;
            state = 'setup_1';
            ui({ title: name, hint: 'Choisissez un mot de passe (min. 8 caractères).', btn: 'Continuer', showBack: true });
            break;
        }

        case 'setup_1':
            if (v.length < 8) { $('lockErr').textContent = 'Minimum 8 caractères.'; return; }
            tmpPwd = v; state = 'setup_2';
            ui({ title: getUsers().find(u=>u.id===currentUserId)?.name||'Notes', hint:'Confirmez votre mot de passe.', btn:'Créer', showBack: true });
            break;

        case 'setup_2':
            if (v !== tmpPwd) {
                tmpPwd = null; state = 'setup_1';
                ui({ hint:'Choisissez un mot de passe (min. 8 caractères).', btn:'Continuer', err:'Les mots de passe ne correspondent pas.', showBack: true });
                return;
            }
            _vault.setKey(await createVault(tmpPwd)); _vault.setNotes([]); _vault.setAppts([]); tmpPwd = null;
            showApp();
            break;

        case 'unlock': {
            /* Délai exponentiel en RAM — non contournable sans rechargement de page */
            const BACKOFF = [0, 1000, 3000, 10000, 30000];
            const delay   = BACKOFF[Math.min(fails, BACKOFF.length - 1)];
            if (delay > 0) {
                $('lockBtn').disabled   = true;
                $('lockInput').disabled = true;
                $('lockErr').textContent = `Patientez ${delay / 1000}s…`;
                await new Promise(r => setTimeout(r, delay));
                $('lockBtn').disabled   = false;
                $('lockInput').disabled = false;
                $('lockErr').textContent = '';
            }
            const r = await tryUnlock(v);
            if (r) {
                fails = 0;
                sessionStorage.removeItem(failsKey(currentUserId));
                localStorage.removeItem(blockKey(currentUserId));
                _vault.setKey(r.key); _vault.setNotes(r.notes); _vault.setAppts(r.appointments);
                /* Auto-upgrade vault legacy (100k SHA-256 → 600k SHA-512) */
                const vp = JSON.parse(localStorage.getItem(vaultParamsKey(currentUserId)) || 'null');
                if (!vp || vp.iter < NEW_VAULT_PARAMS.iter) {
                    await reencrypt(v);
                    secAudit('VAULT_UPGRADED', '600k SHA-512');
                }
                showApp();
            } else {
                fails++;
                secAudit('LOGIN_FAIL', `attempt ${fails}/${MAX_ATT}`);
                sessionStorage.setItem(failsKey(currentUserId), String(fails));
                $('lockInput').value = '';
                if (fails >= MAX_ATT) {
                    blockedUntil = Date.now() + BLOCK_MS;
                    localStorage.setItem(blockKey(currentUserId), String(blockedUntil));
                    fails = 0;
                    sessionStorage.removeItem(failsKey(currentUserId));
                    secAudit('ACCOUNT_BLOCKED', '2 min');
                    $('lockErr').textContent = 'Accès bloqué 2 minutes.';
                } else {
                    const left = MAX_ATT - fails;
                    $('lockErr').textContent = 'Mot de passe incorrect.';
                    $('lockAtt').textContent = `${left} essai${left>1?'s':''} restant${left>1?'s':''}.`;
                }
            }
            break;
        }

        case 'ch0': {
            const r = await tryUnlock(v);
            if (!r) { $('lockErr').textContent = 'Mot de passe actuel incorrect.'; $('lockInput').value=''; return; }
            _vault.setKey(r.key); _vault.setNotes(r.notes); _vault.setAppts(r.appointments); state = 'ch1';
            ui({ hint:'Nouveau mot de passe (min. 8 caractères).', btn:'Continuer' });
            break;
        }
        case 'ch1':
            if (v.length < 8) { $('lockErr').textContent = 'Minimum 8 caractères.'; return; }
            tmpPwd = v; state = 'ch2';
            ui({ hint:'Confirmez le nouveau mot de passe.', btn:'Enregistrer' });
            break;

        case 'ch2':
            if (v !== tmpPwd) {
                tmpPwd = null; state = 'ch1';
                ui({ hint:'Nouveau mot de passe (min. 8 caractères).', btn:'Continuer', err:'Mots de passe différents.' });
                return;
            }
            await reencrypt(tmpPwd); tmpPwd = null;
            showApp();
            break;
    }
}

function startChangePwd() {
    state = 'ch0';
    ui({ hint:'Entrez votre mot de passe actuel.', btn:'Vérifier' });
}

function togglePwd() {
    const i = $('lockInput'), h = i.type==='password';
    i.type = h ? 'text' : 'password';
    i.className = h ? '' : 'pw';
    $('eyeIco').className = h ? 'fas fa-eye-slash' : 'fas fa-eye';
}

let hiddenAt = 0;
const HIDDEN_LOCK_DELAY = 30_000; // verrouillage si l'onglet est caché plus de 30s
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        hiddenAt = Date.now();
        /* Accélérer le timer à 30s dès que l'onglet est caché */
        if (_vault.isOpen()) {
            clearTimeout(lockTimer);
            lockTimer = setTimeout(lockApp, HIDDEN_LOCK_DELAY);
        }
    } else {
        if (hiddenAt && Date.now() - hiddenAt >= LOCK_TIMEOUT) {
            lockApp();
        } else {
            resetTimer(); /* restaurer le timer normal au retour */
        }
        hiddenAt = 0;
    }
});
['click','keydown','mousemove','touchstart'].forEach(e =>
    document.addEventListener(e, () => { if ($('appContent').classList.contains('show')) resetTimer(); }, { passive:true })
);
showLock();

/* ── Notes ── */
let activeNoteId = null;
let selectMode   = false;
let selected     = new Set();

function fmtD(iso) {
    if (!iso) return '';
    if (iso.includes('-')) { const [y,m,d]=iso.split('-'); return `${d}/${m}/${y}`; }
    return iso;
}
function rSt(iso) {
    if (!iso) return null;
    const t = new Date().toISOString().split('T')[0];
    return iso < t ? 'overdue' : iso===t ? 'today' : 'future';
}
function rLbl(s) { return s==='overdue' ? 'En retard' : s==='today' ? "Aujourd'hui" : 'À venir'; }

async function addNote() {
    let title, cat, text;
    try {
        title = validateStr($('fTitle').value, 200, 'Titre');
        cat   = validateStr($('fCat').value, 100, 'Catégorie') || 'Général';
        text  = validateStr($('fText').value, 50_000, 'Contenu');
    } catch (e) { alert(e.message); return; }
    const reminder = $('fDate').value || null;
    if (!text) { $('fText').focus(); return; }

    if (reminder) {
        const today = new Date().toISOString().split('T')[0];
        if (!/^\d{4}-\d{2}-\d{2}$/.test(reminder) || reminder < today) {
            $('dateErr').style.display = 'block';
            $('fDate').focus();
            return;
        }
    }
    $('dateErr').style.display = 'none';

    _vault.addNote({
        id:   Date.now(),
        title: title || text.split('\n')[0].substring(0, 50) || 'Note',
        category: cat, text,
        created:  new Date().toISOString().split('T')[0],
        reminderDate: reminder
    });
    secAudit('NOTE_CREATE');
    await persist();
    ['fTitle','fCat','fText','fDate'].forEach(id => $(id).value = '');
    onSearch();
    $('fText').focus();
}

async function delNote(id) {
    if (!confirm('Supprimer cette note ?')) return;
    _vault.filterNotes(n => n.id !== id);
    secAudit('NOTE_DELETE');
    await persist();
    onSearch();
}

/* ── Bulk select ── */
function enterSelect() {
    selectMode = true; selected.clear();
    $('nlist').classList.add('select-mode');
    $('bulkBar').classList.add('show');
    $('bulkToggle').textContent = 'Tout sélectionner';
    updateBulkCount();
    render($('searchIn').value.trim().toLowerCase());
}

function exitSelect() {
    selectMode = false; selected.clear();
    $('nlist').classList.remove('select-mode');
    $('bulkBar').classList.remove('show');
    $('bulkToggle').textContent = 'Sélectionner';
    render($('searchIn').value.trim().toLowerCase());
}

function toggleSelect(id, cb) {
    if (cb.checked) selected.add(id); else selected.delete(id);
    updateBulkCount();
}

function updateBulkCount() {
    $('bulkCt').textContent = `${selected.size} sélectionnée${selected.size>1?'s':''}`;
}

async function deleteSelected() {
    if (!selected.size) return;
    if (!confirm(`Supprimer ${selected.size} note${selected.size>1?'s':''} ?`)) return;
    _vault.filterNotes(n => !selected.has(n.id));
    await persist();
    exitSelect();
}

async function delFromModal() { await delNote(activeNoteId); closeNote(); }

function openNote(id) {
    const n = _vault.getNotes().find(n=>n.id===id);
    if (!n) return;
    activeNoteId = id;
    $('mTitle').textContent = n.title;
    const rs = rSt(n.reminderDate);
    const badge = rs ? `<span class="rbadge ${rs}"><i class="fas fa-bell"></i> ${fmtD(n.reminderDate)} — ${rLbl(rs)}</span>` : '';
    const closedBadge = n.closed ? `<span class="rbadge closed"><i class="fas fa-circle-check"></i> Clôturée</span>` : '';
    $('mMeta').innerHTML = `<span>${esc(n.category)}</span><span>·</span><span>${fmtD(n.created)}</span>${badge?'<span>·</span>'+badge:''}${closedBadge?'<span>·</span>'+closedBadge:''}`;
    $('mBody').textContent = n.text;
    const btn = $('mBtnClose');
    if (n.closed) {
        btn.className = 'btn-reopen';
        btn.innerHTML = '<i class="fas fa-rotate-left"></i> Réactiver';
    } else {
        btn.className = 'btn-close';
        btn.innerHTML = '<i class="fas fa-circle-check"></i> Clôturer';
    }
    $('noteOv').classList.add('show');
}

async function toggleCloseNote() {
    const n = _vault.getNotes().find(n => n.id === activeNoteId);
    if (!n) return;
    n.closed = !n.closed;
    await persist();
    onSearch();
    openNote(activeNoteId);
}
function closeNote() {
    $('noteOv').classList.remove('show');
    activeNoteId = null;
    exitEditMode();
}

function enterEditMode() {
    const n = _vault.getNotes().find(n => n.id === activeNoteId);
    if (!n) return;
    $('mBody').style.display     = 'none';
    $('mEditForm').style.display = '';
    $('mBtnEdit').style.display  = 'none';
    $('mBtnSave').style.display  = '';
    $('mBtnCancel').textContent  = 'Annuler';
    $('mBtnCancel').dataset.mode = 'edit';
    $('mEditTitle').value = n.title;
    $('mEditCat').value   = n.category;
    $('mEditText').value  = n.text;
    $('mEditDate').value  = n.reminderDate || '';
}

function exitEditMode() {
    $('mBody').style.display     = '';
    $('mEditForm').style.display = 'none';
    $('mBtnEdit').style.display  = '';
    $('mBtnSave').style.display  = 'none';
    $('mBtnCancel').textContent  = 'Fermer';
    delete $('mBtnCancel').dataset.mode;
}

async function saveEditedNote() {
    const n = _vault.getNotes().find(n => n.id === activeNoteId);
    if (!n) return;
    let title, cat, text;
    try {
        title = validateStr($('mEditTitle').value, 200, 'Titre');
        cat   = validateStr($('mEditCat').value, 100, 'Catégorie') || 'Général';
        text  = validateStr($('mEditText').value, 50_000, 'Contenu');
    } catch (e) { alert(e.message); return; }
    if (!text) { $('mEditText').focus(); return; }
    const dl = $('mEditDate').value || null;
    if (dl) {
        const today = new Date().toISOString().split('T')[0];
        if (!/^\d{4}-\d{2}-\d{2}$/.test(dl) || dl < today) {
            alert('La deadline doit être aujourd\'hui ou dans le futur.'); return;
        }
    }
    n.title        = title || text.split('\n')[0].substring(0, 50) || 'Note';
    n.category     = cat;
    n.text         = text;
    n.reminderDate = dl;
    await persist();
    onSearch();
    openNote(activeNoteId);
    exitEditMode();
}

/* ── Reminders ── */
function checkRem() {
    const t = new Date().toISOString().split('T')[0];
    const due = _vault.getNotes().filter(n=>n.reminderDate && n.reminderDate<=t);
    if (!due.length) return;
    const td = due.filter(n=>n.reminderDate===t).length;
    const ov = due.filter(n=>n.reminderDate<t).length;
    $('ribbonTxt').innerHTML = td && ov
        ? `<b>${td}</b> rappel${td>1?'s':''} aujourd'hui · <b>${ov}</b> en retard`
        : td ? `<b>${td}</b> rappel${td>1?'s':''} pour aujourd'hui`
             : `<b>${ov}</b> rappel${ov>1?'s':''} en retard`;
    $('ribbon').classList.add('show');
}

function openRem() {
    const t = new Date().toISOString().split('T')[0];
    const due = _vault.getNotes().filter(n=>n.reminderDate && n.reminderDate<=t);
    $('remList').innerHTML = due.map(n => {
        const s = rSt(n.reminderDate);
        return `<div class="rem-item ${s}" data-noteid="${n.id}">
            <div class="rem-dot"></div>
            <div>
                <div class="rem-t">${esc(n.title)}</div>
                <div class="rem-w">${s==='today'?"Aujourd'hui":'En retard — '+fmtD(n.reminderDate)}</div>
            </div>
        </div>`;
    }).join('');
    $('remOv').classList.add('show');
    $('ribbon').classList.remove('show');
}
function closeRem() { $('remOv').classList.remove('show'); }

/* ── Search + render ── */
function onSearch() {
    const q = $('searchIn').value.trim().toLowerCase();
    $('searchClr').classList.toggle('on', q.length>0);
    render(q);
}
function clearSrc() { $('searchIn').value=''; onSearch(); }

function hl(html, q) {
    if (!q) return html;
    return html.replace(new RegExp(`(${q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')})`, 'gi'), '<mark>$1</mark>');
}

let _closedFilter = false;

function render(q='', recentLimit=null, catFilter=null) {
    const el = $('nlist');
    const _n  = _vault.getNotes();
    let pool = _closedFilter ? _n.filter(n => n.closed) : _n.filter(n => !n.closed);
    let items = q ? pool.filter(n =>
        n.title.toLowerCase().includes(q) ||
        n.text.toLowerCase().includes(q)  ||
        n.category.toLowerCase().includes(q)) : pool;
    if (catFilter)   items = items.filter(n => n.category === catFilter);
    if (recentLimit) items = [...items].sort((a,b) => b.id - a.id).slice(0, recentLimit);
    updateSidebar();
    $('searchCt').textContent = q && items.length!==pool.length ? `${items.length}/${pool.length}` : '';

    if (!items.length) {
        el.innerHTML = q
            ? `<div class="empty"><div class="empty-ico"><i class="fas fa-magnifying-glass"></i></div><p><strong>Aucun résultat</strong>Aucune note pour « ${esc(q)} »</p></div>`
            : _closedFilter
                ? `<div class="empty"><div class="empty-ico"><i class="fas fa-circle-check"></i></div><p><strong>Aucune note clôturée</strong>Les notes terminées apparaîtront ici.</p></div>`
                : `<div class="empty"><div class="empty-ico"><i class="far fa-file-alt"></i></div><p><strong>Aucune note</strong>Créez votre première note.</p></div>`;
        return;
    }

    const g = {};
    items.forEach(n => { (g[n.category]??=[]).push(n); });

    _visibleItems = items;
    $('bulkToggle').classList.toggle('show', items.length > 0);

    el.innerHTML = Object.entries(g).map(([cat, arr]) => `
        <div class="cat-hd">${esc(cat)}</div>
        ${arr.map(n => {
            const rs  = rSt(n.reminderDate);
            const b   = rs ? `<span class="rbadge ${rs}"><i class="fas fa-bell"></i> ${fmtD(n.reminderDate)}</span>` : '';
            const cb  = n.closed ? `<span class="rbadge closed"><i class="fas fa-circle-check"></i> Clôturée</span>` : '';
            const chk = selectMode ? `<input type="checkbox" class="note-check" ${selected.has(n.id)?'checked':''} />` : '';
            return `<div class="note-row${n.closed?' is-closed':''}" data-noteid="${n.id}">
                ${chk}
                <div class="note-body">
                    <div class="note-t">${hl(esc(n.title),q)}</div>
                    <div class="note-foot">
                        <span class="note-date">${fmtD(n.created)}</span>
                        ${b}${cb}
                    </div>
                </div>
                <button class="note-del" title="Supprimer">
                    <i class="fas fa-trash-can"></i>
                </button>
            </div>`;
        }).join('')}
    `).join('');
}

/* ── Compiler ── */
let compileTab = 'cr';

function openCompiler() {
    if (!_vault.getNotes().length) {
        $('compileOv').classList.add('show');
        $('viewCR').innerHTML = '<div class="cr-empty"><i class="far fa-file-alt" style="font-size:24px;display:block;margin-bottom:10px"></i>Aucune note à compiler.</div>';
        $('viewPrompt').style.display = 'none';
        $('viewIA').style.display = 'none';
        $('viewCR').style.display = '';
        $('compileMeta').textContent = '';
        $('tabCR').classList.add('active');
        $('tabPrompt').classList.remove('active');
        $('tabIA').classList.remove('active');
        $('iaGenBtn').style.display = 'none';
        return;
    }
    $('compileScope').value = 'all';
    compileTab = 'cr';
    $('tabCR').classList.add('active');
    $('tabPrompt').classList.remove('active');
    $('tabIA').classList.remove('active');
    $('viewCR').style.display = '';
    $('viewPrompt').style.display = 'none';
    $('viewIA').style.display = 'none';
    $('iaGenBtn').style.display = 'none';
    initApiKeyUI();
    refreshCompiler();
    $('compileOv').classList.add('show');
}

function closeCompiler() { $('compileOv').classList.remove('show'); }

function switchCompileTab(tab) {
    compileTab = tab;
    $('tabCR').classList.toggle('active', tab === 'cr');
    $('tabPrompt').classList.toggle('active', tab === 'prompt');
    $('tabIA').classList.toggle('active', tab === 'ia');
    $('viewCR').style.display     = tab === 'cr'     ? '' : 'none';
    $('viewPrompt').style.display = tab === 'prompt' ? '' : 'none';
    $('viewIA').style.display     = tab === 'ia'     ? '' : 'none';
    $('iaGenBtn').style.display   = tab === 'ia'     ? '' : 'none';
    const labels = { cr: 'Copier le texte', prompt: 'Copier le prompt', ia: 'Copier le résultat' };
    $('copyCompileBtn').innerHTML = `<i class="fas fa-copy"></i> ${labels[tab] || 'Copier'}`;
    $('copyCompileBtn').classList.remove('copied');
}

function getCompileNotes() {
    const allNotes = _vault.getNotes();
    if ($('compileScope').value === 'filtered') {
        const q = $('searchIn').value.trim().toLowerCase();
        if (q) return allNotes.filter(n =>
            n.title.toLowerCase().includes(q) ||
            n.text.toLowerCase().includes(q)  ||
            n.category.toLowerCase().includes(q));
    }
    return allNotes;
}

function groupBy(arr) {
    const g = {};
    arr.forEach(n => { (g[n.category] ??= []).push(n); });
    return g;
}

function refreshCompiler() {
    const list = getCompileNotes();
    const n    = list.length;
    $('compileMeta').textContent = `${n} note${n > 1 ? 's' : ''}`;

    const groups = groupBy(list);

    /* ── Compte rendu view ── */
    if (!n) {
        $('viewCR').innerHTML = '<div class="cr-empty">Aucune note correspondante.</div>';
    } else {
        $('viewCR').innerHTML = Object.entries(groups).map(([cat, items]) =>
            `<div class="cr-cat">${esc(cat)}</div>` +
            items.map(note =>
                `<div class="cr-note">
                    <div class="cr-note-title">${esc(note.title)}</div>
                    ${note.text ? `<div class="cr-note-body">${esc(note.text)}</div>` : ''}
                    <div class="cr-note-meta">
                        <span><i class="fas fa-calendar-days" style="font-size:9px"></i> ${fmtD(note.created)}</span>
                        ${note.reminderDate ? `<span><i class="fas fa-bell" style="font-size:9px"></i> ${fmtD(note.reminderDate)}</span>` : ''}
                    </div>
                </div>`
            ).join('')
        ).join('');
    }

    /* ── Prompt IA ── */
    const today = new Date().toLocaleDateString('fr-FR', { day:'numeric', month:'long', year:'numeric' });
    const userInstr = ($('userInstruction') ? $('userInstruction').value.trim() : '');
    const webSearch = ($('webSearch') ? $('webSearch').checked : false);

    let prompt = '';

    // Demande personnalisée en tête
    if (userInstr) {
        prompt += `Demande : ${userInstr}\n\n`;
    }

    prompt += `Date : ${today}\n\nNotes :\n`;
    for (const [cat, items] of Object.entries(groups)) {
        prompt += `\n[${cat}]\n`;
        items.forEach(note => {
            const preview = note.text.length > 200 ? note.text.slice(0, 200) + '…' : note.text;
            prompt += `• ${note.title}${preview ? ' : ' + preview.replace(/\n/g, ' ') : ''}\n`;
        });
    }

    if (userInstr) {
        prompt += `\nRéponds à la demande ci-dessus en te basant sur ces notes, en français.`;
    } else {
        prompt += `\nTâche : génère un compte rendu structuré en français. Pour chaque point, ajoute un court complément si utile (conseil, ressource, point de vigilance). Format : sections par thème, points clés, compléments en italique.`;
    }
    if (webSearch) {
        prompt += ` Utilise la recherche web pour enrichir avec des informations récentes si pertinent.`;
    }

    $('promptTa').value = prompt;

    // Estimation tokens (~4 chars/token)
    const tokenEst = $('tokenEst');
    if (tokenEst) {
        const est = Math.round(prompt.length / 4);
        tokenEst.textContent = `~${est} tokens`;
        tokenEst.style.color = est > 2000 ? 'var(--amber)' : 'var(--ink-4)';
    }
}

/* ── Groq API ── */
/* ── Encrypted API key storage ── */
async function saveGroqKey(rawKey) {
    if (!rawKey || !_vault.isOpen()) return;
    const encrypted = await cryptEnc({ k: rawKey }, _vault.getKey());
    localStorage.setItem(groqKey(), encrypted);
}

async function loadGroqKey() {
    const stored = localStorage.getItem(groqKey());
    if (!stored || !_vault.isOpen()) return '';
    if (stored.startsWith('gsk_')) {
        await saveGroqKey(stored);
        return stored;
    }
    try {
        const data = await cryptDec(stored, _vault.getKey());
        return data.k || '';
    } catch { return ''; }
}

function hasGroqKey() { return !!localStorage.getItem(groqKey()); }

function initApiKeyUI() {
    if ($('iaApiKey')) {
        $('iaApiKey').value = '';
        $('iaApiKey').placeholder = hasGroqKey()
            ? 'Clé configurée — entrez une nouvelle pour remplacer' : 'gsk_…';
    }
}

function openSettings() {
    const saved = hasGroqKey();
    $('cfgKey').value = '';
    $('cfgKey').placeholder = saved ? 'Clé configurée — entrez une nouvelle pour remplacer' : 'gsk_…';
    const st = $('keyStatus');
    st.className = saved ? 'settings-status ok' : 'settings-status none';
    st.innerHTML  = saved
        ? '<i class="fas fa-lock-open"></i> Clé chiffrée enregistrée'
        : '<i class="fas fa-circle-exclamation"></i> Aucune clé configurée';
    $('settingsOv').classList.add('show');
    setTimeout(() => $('cfgKey').focus(), 80);
}

function closeSettings() { $('settingsOv').classList.remove('show'); }

async function saveKeyInline() {
    const key = $('cfgKey').value.trim();
    if (!key) { closeSettings(); return; }
    await saveGroqKey(key);
    $('cfgKey').value = '';
    $('cfgKey').placeholder = 'Clé configurée — entrez une nouvelle pour remplacer';
    const st = $('keyStatus');
    st.className = 'settings-status ok';
    st.innerHTML = '<i class="fas fa-check-circle"></i> Clé chiffrée et enregistrée';
    const btn = $('btnKeySv');
    const orig = btn.textContent;
    btn.textContent = 'Enregistré !';
    btn.classList.add('saved');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('saved'); closeSettings(); }, 1400);
}

function _groqErrMsg(status) {
    if (status === 401) return 'Clé API invalide — vérifiez vos paramètres.';
    if (status === 429) return 'Quota Groq dépassé — réessayez dans quelques instants.';
    if (status >= 500) return 'Erreur temporaire du service IA — réessayez.';
    return 'Génération impossible — vérifiez votre clé API.';
}


async function saveApiKey() {
    const key = $('iaApiKey')?.value.trim();
    if (!key) return;
    await saveGroqKey(key);
    const btn = $('iaKeySaveBtn');
    if (btn) { btn.textContent = 'Sauvegardé !'; btn.classList.add('saved'); setTimeout(() => { btn.textContent = 'Sauvegarder'; btn.classList.remove('saved'); }, 2000); }
}

function buildIAPrompt() {
    const list   = getCompileNotes();
    const groups = groupBy(list);
    const today  = new Date().toLocaleDateString('fr-FR', { day:'numeric', month:'long', year:'numeric' });
    const instr  = $('iaInstruction').value.trim();
    let prompt = '';
    if (instr) prompt += `Demande : ${instr}\n\n`;
    prompt += `Date : ${today}\n\nNotes :\n`;
    for (const [cat, items] of Object.entries(groups)) {
        prompt += `\n[${cat}]\n`;
        items.forEach(n => {
            const preview = n.text.length > 300 ? n.text.slice(0, 300) + '…' : n.text;
            prompt += `• ${n.title}${preview ? ' : ' + preview.replace(/\n/g, ' ') : ''}\n`;
        });
    }
    if (instr) {
        prompt += `\nRéponds à la demande ci-dessus en te basant sur ces notes, en français.`;
    } else {
        prompt += `\nTâche : génère un compte rendu structuré en français. Pour chaque point, ajoute un court complément si utile. Format : sections par thème, points clés.`;
    }
    return prompt;
}

async function generateWithOpenAI() {
    const apiKey = $('iaApiKey')?.value.trim() || await loadGroqKey();
    if (!apiKey) {
        $('iaResult').innerHTML = '<div class="ia-result-empty" style="color:var(--red)">Clé API manquante — entrez votre clé gsk_… puis sauvegardez.</div>';
        return;
    }

    const genBtn = $('iaGenBtn');
    genBtn.disabled = true;
    genBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Génération…';
    $('iaResult').innerHTML = '<div class="ia-result-empty"><i class="fas fa-circle-notch fa-spin" style="font-size:20px;color:var(--khaki);display:block;margin-bottom:8px"></i>Interrogation de Groq…</div>';
    $('iaUsage').textContent = '';

    const model = $('iaModel').value;

    try {
        const resp = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model,
                max_tokens: 2048,
                messages: [{ role: 'user', content: buildIAPrompt() }]
            })
        });

        const data = await resp.json();
        if (!resp.ok) throw new Error(_groqErrMsg(resp.status));

        /* Validate response structure before using */
        const text = data?.choices?.[0]?.message?.content;
        if (typeof text !== 'string') throw new Error('Réponse inattendue du service IA.');
        if (text.trim()) {
            $('iaResult').textContent = text.trim();
        } else {
            $('iaResult').innerHTML = '<div class="ia-result-empty" style="color:var(--amber)">Réponse vide reçue.</div>';
        }

        if (data.usage?.prompt_tokens != null) {
            $('iaUsage').textContent = `${data.usage.prompt_tokens} tokens entrée · ${data.usage.completion_tokens} tokens sortie`;
        }
    } catch (err) {
        $('iaResult').innerHTML = `<div class="ia-result-empty" style="color:var(--red)">${esc(err.message)}</div>`;
    } finally {
        genBtn.disabled = false;
        genBtn.innerHTML = '<i class="fas fa-wand-magic-sparkles"></i> Générer';
    }
}


async function copyCompiled() {
    const text = compileTab === 'cr'
        ? $('viewCR').innerText.trim()
        : compileTab === 'ia'
            ? $('iaResult').innerText.trim()
            : $('promptTa').value;
    const btn = $('copyCompileBtn');
    try {
        await navigator.clipboard.writeText(text);
    } catch {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;left:-9999px;top:0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    }
    const orig = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-check"></i> Copié !';
    btn.classList.add('copied');
    setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('copied'); }, 2200);
}

/* ═══════════════════════════════════════
   CALENDRIER
   ═══════════════════════════════════════ */

let calYear  = new Date().getFullYear();
let calMonth = new Date().getMonth();
let calSelectedDate = null;
let editingApptId   = null;

const MONTHS_FR = ['Janvier','Février','Mars','Avril','Mai','Juin',
                   'Juillet','Août','Septembre','Octobre','Novembre','Décembre'];
const DAYS_FR   = ['Lun','Mar','Mer','Jeu','Ven','Sam','Dim'];

function catClass(cat) {
    if (cat === 'Personnel') return 'cat-perso';
    if (cat === 'Autre')     return 'cat-autre';
    return '';
}

function renderCalendar() {
    $('calMonthLbl').textContent = `${MONTHS_FR[calMonth]} ${calYear}`;

    // Weekday headers
    $('calWdays').innerHTML = DAYS_FR.map((d,i) =>
        `<div class="cal-wday${i>=5?' weekend':''}">${d}</div>`
    ).join('');

    const today = new Date().toISOString().split('T')[0];
    const firstDay = new Date(calYear, calMonth, 1);
    const lastDay  = new Date(calYear, calMonth + 1, 0);

    // Monday-based offset (0=Mon…6=Sun)
    let startOff = (firstDay.getDay() + 6) % 7;
    const totalCells = startOff + lastDay.getDate();
    const rows = Math.ceil(totalCells / 7);

    let html = '';
    for (let i = 0; i < rows * 7; i++) {
        const dayNum = i - startOff + 1;
        if (dayNum < 1 || dayNum > lastDay.getDate()) {
            html += `<div class="cal-cell other-month"></div>`;
            continue;
        }
        const dateStr = `${calYear}-${String(calMonth+1).padStart(2,'0')}-${String(dayNum).padStart(2,'0')}`;
        const dayAppts = _vault.getAppts().filter(a => a.date === dateStr);
        const isToday    = dateStr === today;
        const isSelected = dateStr === calSelectedDate;
        const dots = dayAppts.slice(0, 3).map(a =>
            `<div class="cal-dot ${catClass(a.category)}"></div>`
        ).join('');
        html += `<div class="cal-cell${isToday?' today':''}${isSelected?' selected':''}" data-date="${dateStr}">
            <div class="cal-day-num">${dayNum}</div>
            <div class="cal-dots">${dots}</div>
        </div>`;
    }
    $('calGrid').innerHTML = html;
}

function calSelectDay(dateStr) {
    calSelectedDate = dateStr;
    renderCalendar();

    const d     = new Date(dateStr + 'T00:00:00');
    const label = d.toLocaleDateString('fr-FR', { weekday:'long', day:'numeric', month:'long' });
    $('calDayLbl').textContent = label.charAt(0).toUpperCase() + label.slice(1);

    const dayAppts = _vault.getAppts()
        .filter(a => a.date === dateStr)
        .sort((a,b) => (a.startTime||'').localeCompare(b.startTime||''));

    $('calDaySub').textContent = dayAppts.length
        ? `${dayAppts.length} rendez-vous`
        : 'Aucun rendez-vous';

    $('calAddBtn').style.display = '';

    if (!dayAppts.length) {
        $('calApptList').innerHTML = `<div class="cal-appt-empty">
            <i class="fas fa-calendar-check"></i>
            Journée libre — cliquez sur <strong>Ajouter</strong> pour planifier
        </div>`;
        return;
    }

    $('calApptList').innerHTML = dayAppts.map(a => {
        const timeStr = a.startTime
            ? `${a.startTime}${a.endTime ? ' → ' + a.endTime : ''}`
            : '';
        return `<div class="appt-row" data-apptid="${a.id}">
            <div class="appt-stripe ${catClass(a.category)}"></div>
            <div class="appt-body">
                <div class="appt-title">${esc(a.title)}</div>
                ${timeStr ? `<div class="appt-time"><i class="fas fa-clock" style="font-size:10px"></i>${timeStr}</div>` : ''}
                ${a.location ? `<div class="appt-desc"><i class="fas fa-location-dot" style="font-size:10px;margin-right:3px"></i>${esc(a.location)}</div>` : ''}
                ${a.description ? `<div class="appt-desc">${esc(a.description)}</div>` : ''}
            </div>
            <button class="appt-del" data-apptdel="${a.id}" title="Supprimer">
                <i class="fas fa-trash-can"></i>
            </button>
        </div>`;
    }).join('');
}

function calPrev() {
    if (calMonth === 0) { calMonth = 11; calYear--; } else calMonth--;
    renderCalendar();
    if (calSelectedDate) calSelectDay(calSelectedDate);
}
function calNext() {
    if (calMonth === 11) { calMonth = 0; calYear++; } else calMonth++;
    renderCalendar();
    if (calSelectedDate) calSelectDay(calSelectedDate);
}

function openApptModal(idOrNull) {
    editingApptId = (idOrNull && typeof idOrNull === 'string' && _vault.getAppts().find(a => a.id == idOrNull))
        ? idOrNull : null;

    if (editingApptId) {
        const a = _vault.getAppts().find(a => a.id == editingApptId);
        $('apptModalTitle').textContent = 'Modifier le rendez-vous';
        $('apptTitle').value    = a.title;
        $('apptDate').value     = a.date;
        $('apptCat').value      = a.category || 'Travail';
        $('apptStart').value    = a.startTime || '';
        $('apptEnd').value      = a.endTime   || '';
        $('apptLocation').value = a.location  || '';
        $('apptDesc').value     = a.description || '';
        $('apptBtnDel').style.display = '';
    } else {
        $('apptModalTitle').textContent = 'Nouveau rendez-vous';
        $('apptTitle').value    = '';
        $('apptDate').value     = calSelectedDate || new Date().toISOString().split('T')[0];
        $('apptCat').value      = 'Travail';
        $('apptStart').value    = '';
        $('apptEnd').value      = '';
        $('apptLocation').value = '';
        $('apptDesc').value     = '';
        $('apptBtnDel').style.display = 'none';
    }
    $('apptOv').classList.add('show');
    setTimeout(() => $('apptTitle').focus(), 80);
}

function closeApptModal() { $('apptOv').classList.remove('show'); editingApptId = null; }

async function saveAppt() {
    const title = $('apptTitle').value.trim();
    if (!title) { $('apptTitle').focus(); return; }
    const date  = $('apptDate').value;
    if (!date)  { $('apptDate').focus(); return; }

    if (editingApptId) {
        const a = _vault.getAppts().find(a => a.id == editingApptId);
        if (a) {
            a.title       = title.substring(0, 200);
            a.date        = date;
            a.category    = $('apptCat').value;
            a.startTime   = $('apptStart').value;
            a.endTime     = $('apptEnd').value;
            a.location    = $('apptLocation').value.trim().substring(0, 200);
            a.description = $('apptDesc').value.trim().substring(0, 2000);
        }
    } else {
        _vault.addAppt({
            id:          Date.now(),
            title:       title.substring(0, 200),
            date,
            category:    $('apptCat').value,
            startTime:   $('apptStart').value,
            endTime:     $('apptEnd').value,
            location:    $('apptLocation').value.trim().substring(0, 200),
            description: $('apptDesc').value.trim().substring(0, 2000),
        });
    }
    await persist();
    closeApptModal();
    renderCalendar();
    updateSidebar();
    if (calSelectedDate) calSelectDay(calSelectedDate);
}

async function delAppt(id) {
    _vault.filterAppts(a => a.id != id);
    await persist();
    renderCalendar();
    updateSidebar();
    if (calSelectedDate) calSelectDay(calSelectedDate);
}
async function delApptFromModal() {
    if (!editingApptId) return;
    await delAppt(editingApptId);
    closeApptModal();
}

/* ── Sauvegarde locale ── */
function exportVault() {
    if (!currentUserId) return;
    const salt   = localStorage.getItem(saltKey(currentUserId));
    const vault  = localStorage.getItem(dataKey(currentUserId));
    const params = localStorage.getItem(vaultParamsKey(currentUserId));
    if (!salt || !vault) {
        setBkStatus('Aucune donnée à exporter.', 'err'); return;
    }
    const name = getUsers().find(u => u.id === currentUserId)?.name || 'Notics';
    const blob = new Blob([JSON.stringify({
        _v: 2, userId: currentUserId, user: name,
        salt, params, vault, exported: new Date().toISOString()
    })], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `notics-${name.replace(/[^a-z0-9]/gi,'_')}-${new Date().toISOString().slice(0,10)}.notics`;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
    setBkStatus('✓ Sauvegarde téléchargée', 'ok');
}

function importVault() { $('importFile').click(); }

function handleImportFile(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
        try {
            const bk = JSON.parse(ev.target.result);
            if (!bk.salt || !bk.vault) throw new Error('Fichier invalide.');
            const uid  = bk.userId || ('imp_' + Date.now());
            const uname = bk.user  || 'Notes importées';
            localStorage.setItem(saltKey(uid),  bk.salt);
            localStorage.setItem(dataKey(uid),  bk.vault);
            if (bk.params) localStorage.setItem(vaultParamsKey(uid), bk.params);
            const users = getUsers();
            if (!users.find(u => u.id === uid)) {
                users.push({ id: uid, name: uname }); saveUsers(users);
            }
            setBkStatus('✓ Importé — verrouillez puis sélectionnez votre profil.', 'ok');
        } catch (err) {
            setBkStatus('✗ ' + err.message, 'err');
        }
        e.target.value = '';
    };
    reader.readAsText(file);
}

function setBkStatus(msg, cls) {
    const el = $('backupStatus');
    el.textContent = msg; el.className = `settings-status ${cls}`;
    setTimeout(() => { el.textContent = ''; el.className = 'settings-status none'; }, 4000);
}

/* ── Variable pour la sélection groupée ── */
let _visibleItems = [];

/* ── Initialisation des écouteurs d'événements ── */
function initEventListeners() {
    /* Lock screen */
    $('lockInput').addEventListener('keydown', e => { if (e.key === 'Enter') handleLock(); });
    $('lockEye').addEventListener('click', togglePwd);
    $('lockBtn').addEventListener('click', handleLock);
    $('backLink').addEventListener('click', showSelectUser);
    $('changePwdLink').addEventListener('click', startChangePwd);

    /* Sidebar */
    $('sbNewBtn').addEventListener('click', () => $('fTitle').focus());
    $('sbAll').addEventListener('click',    () => sbFilter(null, $('sbAll')));
    $('sbRecent').addEventListener('click', () => sbFilter('recent', $('sbRecent')));
    $('sbCal').addEventListener('click',    () => sbFilter('calendar', $('sbCal')));
    $('sbClosed').addEventListener('click', () => sbFilter('closed', $('sbClosed')));
    $('sbSettingsBtn').addEventListener('click', openSettings);
    $('sbLockBtn').addEventListener('click', lockApp);

    /* Ribbon */
    $('ribbonViewBtn').addEventListener('click', openRem);
    $('ribbonCloseBtn').addEventListener('click', () => $('ribbon').classList.remove('show'));

    /* Composer */
    $('btnAddNote').addEventListener('click', addNote);
    $('searchIn').addEventListener('input', onSearch);
    $('searchClr').addEventListener('click', clearSrc);

    /* Sélection groupée */
    $('bulkToggle').addEventListener('click', () => {
        if (selectMode) {
            _visibleItems.forEach(n => selected.add(n.id));
            updateBulkCount();
            render($('searchIn').value.trim().toLowerCase());
        } else {
            enterSelect();
        }
    });
    $('bulkCancelBtn').addEventListener('click', exitSelect);
    $('bulkDelBtn').addEventListener('click', deleteSelected);

    /* Calendrier */
    $('calNavPrev').addEventListener('click', calPrev);
    $('calNavNext').addEventListener('click', calNext);
    $('calAddBtn').addEventListener('click', () => openApptModal());

    /* Modal paramètres */
    $('closeSettingsBtn').addEventListener('click', closeSettings);
    $('cfgKey').addEventListener('keydown', e => { if (e.key === 'Enter') saveKeyInline(); });
    $('btnKeySv').addEventListener('click', saveKeyInline);
    $('btnExport').addEventListener('click', exportVault);
    $('btnImport').addEventListener('click', importVault);
    $('importFile').addEventListener('change', handleImportFile);

    /* Modal note */
    $('closeNoteBtn').addEventListener('click', closeNote);
    $('mBtnDel').addEventListener('click', delFromModal);
    $('mBtnCancel').addEventListener('click', () => {
        if ($('mBtnCancel').dataset.mode === 'edit') exitEditMode();
        else closeNote();
    });
    $('mBtnClose').addEventListener('click', toggleCloseNote);
    $('mBtnEdit').addEventListener('click', enterEditMode);
    $('mBtnSave').addEventListener('click', saveEditedNote);

    /* Modal rendez-vous */
    $('closeApptBtn').addEventListener('click', closeApptModal);
    $('apptBtnDel').addEventListener('click', delApptFromModal);
    $('apptCancelBtn').addEventListener('click', closeApptModal);
    $('apptSaveBtn').addEventListener('click', saveAppt);

    /* Modal rappels */
    $('closeRemBtn').addEventListener('click', closeRem);
    $('closeRemBtn2').addEventListener('click', closeRem);

    /* Modal compilateur */
    $('closeCompilerBtn').addEventListener('click', closeCompiler);
    $('closeCompilerBtn2').addEventListener('click', closeCompiler);
    $('tabCR').addEventListener('click', () => switchCompileTab('cr'));
    $('tabPrompt').addEventListener('click', () => switchCompileTab('prompt'));
    $('compileScope').addEventListener('change', refreshCompiler);
    $('userInstruction').addEventListener('input', refreshCompiler);
    $('webSearch').addEventListener('change', refreshCompiler);
    $('iaKeySaveBtn').addEventListener('click', saveApiKey);
    $('iaGenBtn').addEventListener('click', generateWithOpenAI);
    $('copyCompileBtn').addEventListener('click', copyCompiled);

    /* Overlays — fermeture au clic extérieur */
    $('noteOv').addEventListener('click',     e => { if (e.target === $('noteOv'))     closeNote(); });
    $('remOv').addEventListener('click',      e => { if (e.target === $('remOv'))      closeRem(); });
    $('compileOv').addEventListener('click',  e => { if (e.target === $('compileOv'))  closeCompiler(); });
    $('settingsOv').addEventListener('click', e => { if (e.target === $('settingsOv')) closeSettings(); });
    $('apptOv').addEventListener('click',     e => { if (e.target === $('apptOv'))     closeApptModal(); });

    /* ── Délégation — éléments dynamiques ── */

    $('userGrid').addEventListener('click', e => {
        const del  = e.target.closest('[data-useridel]');
        if (del)  { e.stopPropagation(); deleteUser(del.dataset.useridel); return; }
        const card = e.target.closest('[data-userid]');
        if (card) { selectUser(card.dataset.userid); return; }
        if (e.target.closest('[data-new-user]')) startNewUser();
    });

    $('sbCats').addEventListener('click', e => {
        const item = e.target.closest('[data-cat]');
        if (item) sbFilter('cat:' + item.dataset.cat, item);
    });

    $('remList').addEventListener('click', e => {
        const item = e.target.closest('[data-noteid]');
        if (item) { closeRem(); openNote(parseInt(item.dataset.noteid, 10)); }
    });

    $('nlist').addEventListener('click', e => {
        const chk = e.target.closest('.note-check');
        if (chk) {
            e.stopPropagation();
            const row = chk.closest('[data-noteid]');
            if (row) toggleSelect(parseInt(row.dataset.noteid, 10), chk);
            return;
        }
        const del = e.target.closest('.note-del');
        if (del) {
            e.stopPropagation();
            const row = del.closest('[data-noteid]');
            if (row) delNote(parseInt(row.dataset.noteid, 10));
            return;
        }
        if (!selectMode) {
            const row = e.target.closest('[data-noteid]');
            if (row) openNote(parseInt(row.dataset.noteid, 10));
        }
    });

    $('calGrid').addEventListener('click', e => {
        const cell = e.target.closest('[data-date]');
        if (cell) calSelectDay(cell.dataset.date);
    });

    $('calApptList').addEventListener('click', e => {
        const del = e.target.closest('[data-apptdel]');
        if (del)  { e.stopPropagation(); delAppt(del.dataset.apptdel); return; }
        const row = e.target.closest('[data-apptid]');
        if (row)  openApptModal(row.dataset.apptid);
    });
}

/* ── Démarrage ── */
initEventListeners();
startPvRotate();
startAwAnimation();
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
}

})(); /* fin IIFE */
