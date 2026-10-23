// LONALOTO — serveur (Express + PostgreSQL)
// Sert le front-end statique, l'état de l'application (une ligne JSONB),
// et désormais l'authentification par comptes (Admin / Activité).

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // Render passe par un proxy : nécessaire pour connaître la vraie IP du client
app.use(express.json({ limit: '5mb' }));

// En-têtes de sécurité de base (sans dépendance supplémentaire)
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  if (process.env.RENDER || process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  }
  next();
});
app.use(cookieParser());

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL manquant. Sur Render, il est fourni automatiquement si render.yaml relie une base de données au service.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const SESSION_COOKIE = 'lonaloto_session';
const SESSION_DURATION_MS = 2 * 60 * 60 * 1000; // 2 heures d'inactivité max
const DEFAULT_PASSWORD = '123456789';   // mot de passe initial des nouveaux comptes
const RESET_PASSWORD = '000000000';     // mot de passe après une réinitialisation par un admin (9 zéros)

// ============================================================
// Schéma (phase 1 : authentification de base, sur l'état existant)
// ============================================================
async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      id INTEGER PRIMARY KEY,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS accounts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      role TEXT NOT NULL CHECK (role IN ('admin', 'activite')),
      identifiant TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      must_change_password BOOLEAN NOT NULL DEFAULT true,
      statut TEXT NOT NULL DEFAULT 'actif' CHECK (statut IN ('actif', 'bloque')),
      activite_nom TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      expires_at TIMESTAMPTZ NOT NULL,
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  // pgcrypto pour gen_random_uuid() — au cas où l'extension ne serait pas déjà active
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto`).catch(() => {});

  // Gestion des comptes : super admin, créateur de chaque compte, état du mot de passe.
  // pw_status : 'initial' (mot de passe de création), 'reset' (réinitialisé à 000000000), 'perso' (choisi par l'utilisateur).
  // Le mot de passe lui-même n'est jamais stocké en clair : seul son hash bcrypt est conservé.
  await pool.query(`
    ALTER TABLE accounts ADD COLUMN IF NOT EXISTS is_super BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE accounts ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES accounts(id) ON DELETE SET NULL;
    ALTER TABLE accounts ADD COLUMN IF NOT EXISTS pw_status TEXT;
  `);
  await pool.query(`UPDATE accounts SET pw_status = CASE WHEN must_change_password THEN 'initial' ELSE 'perso' END WHERE pw_status IS NULL`);
}

async function getSuperAdminId() {
  const r = await pool.query('SELECT id FROM accounts WHERE is_super = true LIMIT 1');
  return r.rows.length ? r.rows[0].id : null;
}

// Garantit qu'un compte activité existe pour chaque nom d'activité de la liste donnée.
// Idempotent (ON CONFLICT DO NOTHING) — peut être rappelée à chaque sauvegarde admin.
// creatorId : le compte admin qui a ajouté l'activité (il pourra ensuite réinitialiser son mot de passe).
async function ensureActivityAccounts(activityNames, creatorId) {
  if (!activityNames || !activityNames.length) return;
  const hash = await bcrypt.hash(DEFAULT_PASSWORD, 10);
  const creator = creatorId || await getSuperAdminId();
  for (const nom of activityNames) {
    const r = await pool.query(
      `INSERT INTO accounts (role, identifiant, password_hash, must_change_password, activite_nom, created_by, pw_status)
       VALUES ('activite', $1, $2, true, $1, $3, 'initial')
       ON CONFLICT (identifiant) DO NOTHING
       RETURNING id`,
      [nom, hash, creator]
    );
    if (r.rows.length) console.log('Nouveau compte activité créé pour "' + nom + '" (mot de passe par défaut ' + DEFAULT_PASSWORD + ')');
  }
}

// Au démarrage : garantit l'admin + les comptes des activités déjà connues (si l'état existe déjà).
async function seedAccountsIfEmpty() {
  const hash = await bcrypt.hash(DEFAULT_PASSWORD, 10);
  await pool.query(
    `INSERT INTO accounts (role, identifiant, password_hash, must_change_password, activite_nom, is_super, pw_status)
     VALUES ('admin', 'admin', $1, true, NULL, true, 'initial')
     ON CONFLICT (identifiant) DO NOTHING`,
    [hash]
  );
  // Le compte « admin » d'origine (le concessionnaire) est le super admin, y compris sur une base existante.
  if (!(await getSuperAdminId())) {
    await pool.query(`UPDATE accounts SET is_super = true, role = 'admin' WHERE identifiant = 'admin'`);
  }
  const superId = await getSuperAdminId();
  // Comptes existants sans créateur connu : rattachés au super admin.
  if (superId) {
    await pool.query('UPDATE accounts SET created_by = $1 WHERE created_by IS NULL AND id <> $1', [superId]);
  }
  const stateRes = await pool.query('SELECT data FROM app_state WHERE id = 1');
  const activities = (stateRes.rows[0] && stateRes.rows[0].data && stateRes.rows[0].data.activities) || [];
  await ensureActivityAccounts(activities);
}

// ============================================================
// Sessions
// ============================================================
async function createSession(accountId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS);
  await pool.query(
    'INSERT INTO sessions (token, account_id, expires_at) VALUES ($1, $2, $3)',
    [token, accountId, expiresAt]
  );
  return { token, expiresAt };
}

async function getSessionAccount(token) {
  if (!token) return null;
  const r = await pool.query(
    `SELECT s.token, s.expires_at, a.id, a.role, a.identifiant, a.statut,
            a.must_change_password, a.activite_nom, a.is_super
     FROM sessions s JOIN accounts a ON a.id = s.account_id
     WHERE s.token = $1`,
    [token]
  );
  if (r.rows.length === 0) return null;
  const row = r.rows[0];
  if (new Date(row.expires_at).getTime() < Date.now()) {
    await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
    return null;
  }
  if (row.statut === 'bloque') return { blocked: true };
  // Session glissante : on prolonge l'expiration à chaque requête authentifiée.
  const newExpiresAt = new Date(Date.now() + SESSION_DURATION_MS);
  await pool.query(
    'UPDATE sessions SET last_seen_at = now(), expires_at = $2 WHERE token = $1',
    [token, newExpiresAt]
  );
  return {
    accountId: row.id,
    role: row.role,
    identifiant: row.identifiant,
    mustChangePassword: row.must_change_password,
    activiteNom: row.activite_nom,
    isSuper: row.is_super
  };
}

function setSessionCookie(res, token) {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production' || !!process.env.RENDER,
    maxAge: SESSION_DURATION_MS
  });
}

const MUST_CHANGE_ALLOWED = ['/api/auth/me', '/api/auth/change-password'];

async function requireAuth(req, res, next) {
  try {
    const token = req.cookies[SESSION_COOKIE];
    const account = await getSessionAccount(token);
    if (!account) return res.status(401).json({ error: 'not_authenticated' });
    if (account.blocked) {
      return res.status(403).json({ error: 'account_blocked', message: 'Votre compte est bloqué, veuillez contacter votre concessionnaire' });
    }
    req.account = account;
    // Mot de passe temporaire : rien d'autre n'est autorisé tant qu'il n'a pas été remplacé.
    if (account.mustChangePassword && !MUST_CHANGE_ALLOWED.includes(req.path)) {
      return res.status(403).json({ error: 'must_change_password', message: 'Vous devez d\'abord choisir un nouveau mot de passe.' });
    }
    next();
  } catch (e) {
    console.error('requireAuth error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
}

function requireAdmin(req, res, next) {
  if (req.account.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  next();
}

// ============================================================
// Limite de tentatives de connexion (anti-devinette des mots de passe par défaut)
// 5 échecs pour un même identifiant ou une même IP → blocage 15 minutes.
// ============================================================
const LOGIN_MAX_FAILS_ID = 5;    // par identifiant
const LOGIN_MAX_FAILS_IP = 20;   // par adresse IP (plus large : plusieurs agents peuvent partager une connexion)
const LOGIN_LOCK_MS = 15 * 60 * 1000;
const loginFails = new Map(); // clé -> { count, until }

function loginMax(k) { return k.startsWith('ip:') ? LOGIN_MAX_FAILS_IP : LOGIN_MAX_FAILS_ID; }
function loginLockedFor(keys) {
  const now = Date.now();
  for (const k of keys) {
    const e = loginFails.get(k);
    if (e && e.until > now) return Math.ceil((e.until - now) / 60000);
  }
  return 0;
}
function loginRecordFail(keys) {
  const now = Date.now();
  for (const k of keys) {
    let e = loginFails.get(k);
    if (!e || (e.until && e.until <= now) || now - e.first > LOGIN_LOCK_MS) e = { count: 0, until: 0, first: now };
    e.count += 1;
    if (e.count >= loginMax(k)) e.until = now + LOGIN_LOCK_MS;
    loginFails.set(k, e);
  }
}
function loginClear(keys) { for (const k of keys) loginFails.delete(k); }
// Nettoyage périodique de la mémoire
setInterval(() => {
  const now = Date.now();
  for (const [k, e] of loginFails) if (e.until <= now && now - e.first > LOGIN_LOCK_MS) loginFails.delete(k);
}, 30 * 60 * 1000).unref();

// Mots de passe connus de tous : interdits comme mot de passe personnel.
const FORBIDDEN_PASSWORDS = [DEFAULT_PASSWORD, RESET_PASSWORD, '00000000', '123456', '12345678', '000000'];

// ============================================================
// Routes d'authentification
// ============================================================
app.post('/api/auth/login', async (req, res) => {
  const { identifiant, password } = req.body || {};
  if (!identifiant || !password) return res.status(400).json({ error: 'missing_fields' });

  const keys = ['ip:' + req.ip, 'id:' + String(identifiant).toLowerCase()];
  const wait = loginLockedFor(keys);
  if (wait) {
    return res.status(429).json({ error: 'too_many_attempts', message: 'Trop de tentatives. Réessayez dans ' + wait + ' minute(s).' });
  }

  try {
    const r = await pool.query('SELECT * FROM accounts WHERE identifiant = $1', [identifiant]);
    if (r.rows.length === 0) { loginRecordFail(keys); return res.status(401).json({ error: 'invalid_credentials' }); }
    const account = r.rows[0];

    if (account.statut === 'bloque') {
      return res.status(403).json({ error: 'account_blocked', message: 'Votre compte est bloqué, veuillez contacter votre concessionnaire' });
    }

    const ok = await bcrypt.compare(password, account.password_hash);
    if (!ok) { loginRecordFail(keys); return res.status(401).json({ error: 'invalid_credentials' }); }
    loginClear(keys);

    const { token } = await createSession(account.id);
    setSessionCookie(res, token);
    res.json({
      role: account.role,
      identifiant: account.identifiant,
      mustChangePassword: account.must_change_password,
      activiteNom: account.activite_nom,
      isSuper: account.is_super
    });
  } catch (e) {
    console.error('POST /api/auth/login error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  const token = req.cookies[SESSION_COOKIE];
  if (token) await pool.query('DELETE FROM sessions WHERE token = $1', [token]).catch(() => {});
  res.clearCookie(SESSION_COOKIE);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({
    role: req.account.role,
    identifiant: req.account.identifiant,
    mustChangePassword: req.account.mustChangePassword,
    activiteNom: req.account.activiteNom,
    isSuper: !!req.account.isSuper
  });
});

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'weak_password', message: 'Le nouveau mot de passe doit faire au moins 6 caractères.' });
  }
  if (FORBIDDEN_PASSWORDS.includes(String(newPassword)) || /^(.)\1+$/.test(String(newPassword))) {
    return res.status(400).json({ error: 'weak_password', message: 'Ce mot de passe est trop simple (mot de passe par défaut ou un seul caractère répété). Choisissez-en un autre.' });
  }
  try {
    const r = await pool.query('SELECT password_hash FROM accounts WHERE id = $1', [req.account.accountId]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'not_found' });

    // Le changement forcé du premier login n'exige pas l'ancien mot de passe (c'est le mot de passe
    // par défaut, connu de tous) ; un changement volontaire ultérieur, lui, l'exige.
    if (!req.account.mustChangePassword) {
      const ok = await bcrypt.compare(currentPassword || '', r.rows[0].password_hash);
      if (!ok) return res.status(401).json({ error: 'wrong_current_password' });
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      "UPDATE accounts SET password_hash = $1, must_change_password = false, pw_status = 'perso', updated_at = now() WHERE id = $2",
      [newHash, req.account.accountId]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/auth/change-password error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

// ============================================================
// État de l'application — désormais protégé, et cloisonné par activité
// ============================================================

// Ne renvoie que ce que le rôle du compte a le droit de voir.
function scopeStateForAccount(fullState, account) {
  if (!fullState) return fullState;
  if (account.role === 'admin') return fullState;

  const nom = account.activiteNom;
  const scoped = Object.assign({}, fullState);
  scoped.activities = [nom];
  scoped.data = { [nom]: (fullState.data && fullState.data[nom]) || {} };
  scoped.activityRates = { [nom]: (fullState.activityRates && fullState.activityRates[nom]) || fullState.defaultRates };
  return scoped;
}

app.get('/api/state', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT data FROM app_state WHERE id = 1');
    const full = r.rows.length ? r.rows[0].data : null;
    res.json(scopeStateForAccount(full, req.account));
  } catch (e) {
    console.error('GET /api/state error:', e.message);
    res.status(500).json({ error: 'db_error' });
  }
});

app.put('/api/state', requireAuth, async (req, res) => {
  const incoming = req.body;
  if (!incoming || typeof incoming !== 'object') {
    return res.status(400).json({ error: 'invalid_body' });
  }
  try {
    if (req.account.role === 'admin') {
      // L'admin peut tout modifier (activités, taux, données) — comportement inchangé.
      await pool.query(
        `INSERT INTO app_state (id, data, updated_at) VALUES (1, $1, now())
         ON CONFLICT (id) DO UPDATE SET data = $1, updated_at = now()`,
        [incoming]
      );
      ensureActivityAccounts(incoming.activities, req.account.accountId).catch((e) => console.error('ensureActivityAccounts error:', e.message));
      return res.json({ ok: true });
    }

    // Un compte activité ne peut écrire QUE dans sa propre section de données,
    // quoi que le corps de la requête contienne par ailleurs (jamais confiance au client).
    const nom = req.account.activiteNom;
    const r = await pool.query('SELECT data FROM app_state WHERE id = 1');
    if (r.rows.length === 0) return res.status(409).json({ error: 'state_not_initialized' });

    const full = r.rows[0].data;
    const ownIncoming = incoming.data && incoming.data[nom];
    if (!ownIncoming) return res.status(400).json({ error: 'invalid_body' });

    full.data = full.data || {};
    full.data[nom] = ownIncoming;

    await pool.query(
      `INSERT INTO app_state (id, data, updated_at) VALUES (1, $1, now())
       ON CONFLICT (id) DO UPDATE SET data = $1, updated_at = now()`,
      [full]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('PUT /api/state error:', e.message);
    res.status(500).json({ error: 'db_error' });
  }
});

// ============================================================
// Gestion des comptes (menu « GESTION DES COMPTES » des paramètres admin)
// Toutes les règles sont vérifiées ici, côté serveur — l'interface ne fait que les refléter.
// ============================================================

// Le super admin voit et gère tous les comptes ; un autre admin ne voit que les comptes qu'il a créés.
function canManageAccount(actor, target) {
  if (!target || target.is_super) return false;          // le super admin est protégé
  if (target.id === actor.accountId) return false;       // son propre mot de passe se change autrement
  if (actor.isSuper) return true;
  return target.created_by === actor.accountId;
}

async function findAccount(id) {
  if (!/^[0-9a-f-]{36}$/i.test(String(id))) return null;
  const r = await pool.query('SELECT id, role, identifiant, is_super, created_by, activite_nom FROM accounts WHERE id = $1', [id]);
  return r.rows[0] || null;
}

app.get('/api/accounts', requireAuth, requireAdmin, async (req, res) => {
  try {
    const params = [];
    let where = '';
    if (!req.account.isSuper) { params.push(req.account.accountId); where = 'WHERE a.created_by = $1'; }
    const r = await pool.query(
      `SELECT a.id, a.identifiant, a.role, a.is_super, a.activite_nom, a.statut, a.pw_status,
              a.must_change_password, a.created_by, c.identifiant AS created_by_identifiant
         FROM accounts a LEFT JOIN accounts c ON c.id = a.created_by
         ${where}
        ORDER BY a.is_super DESC, a.role, a.identifiant`, params
    );
    // Jamais de hash ni de mot de passe dans la réponse : uniquement l'état du mot de passe.
    res.json({
      viewerIsSuper: !!req.account.isSuper,
      viewerId: req.account.accountId,
      resetPassword: RESET_PASSWORD,
      defaultPassword: DEFAULT_PASSWORD,
      accounts: r.rows.map((a) => ({
        id: a.id,
        identifiant: a.identifiant,
        role: a.role,
        isSuper: a.is_super,
        activiteNom: a.activite_nom,
        statut: a.statut,
        pwStatus: a.pw_status,
        createdBy: a.created_by_identifiant,
        canReset: canManageAccount(req.account, a),
        canChangeRole: !!req.account.isSuper && !a.is_super && a.id !== req.account.accountId && !!a.activite_nom
      }))
    });
  } catch (e) {
    console.error('GET /api/accounts error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/accounts/:id/reset-password', requireAuth, requireAdmin, async (req, res) => {
  try {
    const target = await findAccount(req.params.id);
    if (!target) return res.status(404).json({ error: 'not_found', message: 'Compte introuvable.' });
    if (!canManageAccount(req.account, target)) {
      return res.status(403).json({ error: 'forbidden', message: 'Vous ne pouvez réinitialiser que les mots de passe des comptes que vous avez créés.' });
    }
    const hash = await bcrypt.hash(RESET_PASSWORD, 10);
    await pool.query(
      "UPDATE accounts SET password_hash = $1, must_change_password = true, pw_status = 'reset', updated_at = now() WHERE id = $2",
      [hash, target.id]
    );
    // L'utilisateur est déconnecté partout et devra se reconnecter avec 000000000, puis choisir son mot de passe.
    await pool.query('DELETE FROM sessions WHERE account_id = $1', [target.id]);
    console.log('Mot de passe de « ' + target.identifiant + ' » réinitialisé par « ' + req.account.identifiant + ' »');
    res.json({ ok: true, message: 'Mot de passe réinitialisé avec succès' });
  } catch (e) {
    console.error('POST /api/accounts/:id/reset-password error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

// Changement de rôle (agent ⇄ admin) : super admin uniquement.
// Seuls les comptes rattachés à une activité peuvent changer de rôle (un agent a besoin d'une activité).
app.post('/api/accounts/:id/role', requireAuth, requireAdmin, async (req, res) => {
  if (!req.account.isSuper) {
    return res.status(403).json({ error: 'forbidden', message: 'Seul le super admin peut modifier les droits d\'un compte.' });
  }
  const newRole = req.body && req.body.role;
  if (newRole !== 'admin' && newRole !== 'activite') return res.status(400).json({ error: 'invalid_role' });
  const client = await pool.connect();
  try {
    const target = await findAccount(req.params.id);
    if (!target) return res.status(404).json({ error: 'not_found', message: 'Compte introuvable.' });
    if (target.is_super || target.id === req.account.accountId) {
      return res.status(403).json({ error: 'forbidden', message: 'Le rôle du super admin ne peut pas être modifié.' });
    }
    if (!target.activite_nom) {
      return res.status(400).json({ error: 'no_activity', message: 'Ce compte n\'est rattaché à aucune activité : il ne peut pas devenir agent.' });
    }
    if (target.role === newRole) return res.json({ ok: true });
    await client.query('BEGIN');
    if (target.role === 'admin' && newRole === 'activite') {
      // En redevenant agent, les comptes qu'il avait créés sont rattachés au super admin.
      await client.query('UPDATE accounts SET created_by = $1 WHERE created_by = $2', [req.account.accountId, target.id]);
    }
    await client.query('UPDATE accounts SET role = $1, updated_at = now() WHERE id = $2', [newRole, target.id]);
    // Ses droits changent : il doit se reconnecter pour les obtenir.
    await client.query('DELETE FROM sessions WHERE account_id = $1', [target.id]);
    await client.query('COMMIT');
    console.log('Rôle de « ' + target.identifiant + ' » : ' + target.role + ' → ' + newRole + ' (par « ' + req.account.identifiant + ' »)');
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('POST /api/accounts/:id/role error:', e.message);
    res.status(500).json({ error: 'server_error' });
  } finally {
    client.release();
  }
});

app.get('/healthz', (req, res) => res.send('ok'));

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Gestion d'erreur générique : ne jamais renvoyer la pile d'erreur technique au client.
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(400).json({ error: 'bad_request' });
});

const PORT = process.env.PORT || 3000;

ensureTables()
  .then(seedAccountsIfEmpty)
  .then(() => {
    app.listen(PORT, () => console.log('LONALOTO en écoute sur le port ' + PORT));
  })
  .catch((e) => {
    console.error('Impossible d\'initialiser la base de données:', e.message);
    process.exit(1);
  });
