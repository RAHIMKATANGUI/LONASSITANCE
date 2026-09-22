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
app.use(express.json({ limit: '5mb' }));
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
const DEFAULT_PASSWORD = '123456789';

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
}

// Garantit qu'un compte activité existe pour chaque nom d'activité de la liste donnée.
// Idempotent (ON CONFLICT DO NOTHING) — peut être rappelée à chaque sauvegarde admin.
async function ensureActivityAccounts(activityNames) {
  if (!activityNames || !activityNames.length) return;
  const hash = await bcrypt.hash(DEFAULT_PASSWORD, 10);
  for (const nom of activityNames) {
    const r = await pool.query(
      `INSERT INTO accounts (role, identifiant, password_hash, must_change_password, activite_nom)
       VALUES ('activite', $1, $2, true, $1)
       ON CONFLICT (identifiant) DO NOTHING
       RETURNING id`,
      [nom, hash]
    );
    if (r.rows.length) console.log('Nouveau compte activité créé pour "' + nom + '" (mot de passe par défaut ' + DEFAULT_PASSWORD + ')');
  }
}

// Au démarrage : garantit l'admin + les comptes des activités déjà connues (si l'état existe déjà).
async function seedAccountsIfEmpty() {
  const hash = await bcrypt.hash(DEFAULT_PASSWORD, 10);
  await pool.query(
    `INSERT INTO accounts (role, identifiant, password_hash, must_change_password, activite_nom)
     VALUES ('admin', 'admin', $1, true, NULL)
     ON CONFLICT (identifiant) DO NOTHING`,
    [hash]
  );
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
            a.must_change_password, a.activite_nom
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
    activiteNom: row.activite_nom
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

async function requireAuth(req, res, next) {
  try {
    const token = req.cookies[SESSION_COOKIE];
    const account = await getSessionAccount(token);
    if (!account) return res.status(401).json({ error: 'not_authenticated' });
    if (account.blocked) {
      return res.status(403).json({ error: 'account_blocked', message: 'Votre compte est bloqué, veuillez contacter votre concessionnaire' });
    }
    req.account = account;
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
// Routes d'authentification
// ============================================================
app.post('/api/auth/login', async (req, res) => {
  const { identifiant, password } = req.body || {};
  if (!identifiant || !password) return res.status(400).json({ error: 'missing_fields' });

  try {
    const r = await pool.query('SELECT * FROM accounts WHERE identifiant = $1', [identifiant]);
    if (r.rows.length === 0) return res.status(401).json({ error: 'invalid_credentials' });
    const account = r.rows[0];

    if (account.statut === 'bloque') {
      return res.status(403).json({ error: 'account_blocked', message: 'Votre compte est bloqué, veuillez contacter votre concessionnaire' });
    }

    const ok = await bcrypt.compare(password, account.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

    const { token } = await createSession(account.id);
    setSessionCookie(res, token);
    res.json({
      role: account.role,
      identifiant: account.identifiant,
      mustChangePassword: account.must_change_password,
      activiteNom: account.activite_nom
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
    activiteNom: req.account.activiteNom
  });
});

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'weak_password', message: 'Le nouveau mot de passe doit faire au moins 6 caractères.' });
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
      'UPDATE accounts SET password_hash = $1, must_change_password = false, updated_at = now() WHERE id = $2',
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
      ensureActivityAccounts(incoming.activities).catch((e) => console.error('ensureActivityAccounts error:', e.message));
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
