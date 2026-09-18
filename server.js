// LONALOTO — serveur de sauvegarde partagée (Express + PostgreSQL)
// Sert le front-end statique (public/index.html) et une API REST minimale
// qui stocke l'état complet de l'application dans une seule ligne JSONB.

const express = require('express');
const path = require('path');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '5mb' }));

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL manquant. Sur Render, il est fourni automatiquement si render.yaml relie une base de données au service.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function ensureTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      id INTEGER PRIMARY KEY,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
}

// GET /api/state -> renvoie l'état sauvegardé, ou null si la base est vide (premier lancement)
app.get('/api/state', async (req, res) => {
  try {
    const r = await pool.query('SELECT data FROM app_state WHERE id = 1');
    if (r.rows.length === 0) return res.json(null);
    res.json(r.rows[0].data);
  } catch (e) {
    console.error('GET /api/state error:', e.message);
    res.status(500).json({ error: 'db_error' });
  }
});

// PUT /api/state -> remplace l'état sauvegardé par celui envoyé (le front-end envoie l'objet complet)
app.put('/api/state', async (req, res) => {
  const data = req.body;
  if (!data || typeof data !== 'object') {
    return res.status(400).json({ error: 'invalid_body' });
  }
  try {
    await pool.query(
      `INSERT INTO app_state (id, data, updated_at) VALUES (1, $1, now())
       ON CONFLICT (id) DO UPDATE SET data = $1, updated_at = now()`,
      [data]
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

ensureTable()
  .then(() => {
    app.listen(PORT, () => console.log('LONALOTO en écoute sur le port ' + PORT));
  })
  .catch((e) => {
    console.error('Impossible d\'initialiser la base de données:', e.message);
    process.exit(1);
  });
