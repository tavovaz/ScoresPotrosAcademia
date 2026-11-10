// Rutas/apiClaude.js
// API protegida para que un asistente (Claude) lea y corrija estadísticas
// por HTTPS, sin conexión directa a MySQL.
//
// Seguridad:
//  - Solo funciona si existe la variable de entorno CLAUDE_API_TOKEN
//    (si no existe, todas las rutas responden 404).
//  - Cada petición debe traer el header  Authorization: Bearer <token>
//  - Lecturas: solo SELECT/SHOW/DESCRIBE, una sentencia, dentro de una
//    transacción READ ONLY, y nunca sobre UsuarioAdministradores.
//  - Escrituras: solo UPDATE a columnas de estadísticas en tablas
//    permitidas, con WHERE por igualdad, límite de filas y antes/después.

const express = require('express');
const crypto = require('crypto');
const mysql = require('mysql2/promise');

const router = express.Router();

// Pool propio: una sola sentencia por consulta (sin multipleStatements).
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || process.env.DB_DATABASE || 'academia_bd',
  port: Number(process.env.DB_PORT) || 3306,
  connectionLimit: 3,
  multipleStatements: false,
  timezone: 'Z'
});

// Tablas y columnas que se pueden modificar.
const EDITABLE = {
  EstadisticasBateoTemporada: [
    'apariciones_al_bat', 'hits', 'bases_por_bolas', 'carreras',
    'carreras_producidas', 'sencillos', 'dobles', 'triples',
    'home_runs', 'bases_robadas'
  ],
  EstadisticasPitcheoTemporada: [
    'bases_por_bolas', 'victorias', 'derrotas', 'entradas_lanzadas',
    'carreras_limpias', 'ponches'
  ],
  EstadisticasEquipoTemporada: [
    'carreras_en_contra', 'carreras_a_favor', 'ganados', 'perdidos',
    'empatados', 'errores'
  ]
};

// Columnas que se pueden usar en el WHERE de un UPDATE.
const WHERE_COLS = ['id_estadistica', 'id_temporada', 'id_jugador', 'id_equipo_temporada'];

const MAX_ROWS_READ = 500;

// ---------- Autenticación por token ----------
function tokenOk(req) {
  const expected = process.env.CLAUDE_API_TOKEN;
  if (!expected || expected.length < 32) return false;
  const header = req.get('authorization') || '';
  const given = header.startsWith('Bearer ') ? header.slice(7) : '';
  const a = crypto.createHash('sha256').update(given).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

router.use((req, res, next) => {
  if (!process.env.CLAUDE_API_TOKEN) return res.status(404).send('Not found');
  if (!tokenOk(req)) return res.status(401).json({ error: 'unauthorized' });
  res.set('Cache-Control', 'no-store');
  next();
});

// ---------- Lectura ----------
// POST /api/claude/query  { "sql": "SELECT ...", "params": [] }
router.post('/query', async (req, res) => {
  const sql = String(req.body?.sql || '').trim().replace(/;\s*$/, '');
  const params = Array.isArray(req.body?.params) ? req.body.params : [];

  if (!/^(select|show|describe|desc|explain)\s/i.test(sql)) {
    return res.status(400).json({ error: 'Solo se permiten SELECT/SHOW/DESCRIBE' });
  }
  if (sql.includes(';')) {
    return res.status(400).json({ error: 'Solo una sentencia por consulta' });
  }
  if (/usuarioadministradores|into\s+(out|dump)file|load_file|sleep\s*\(|benchmark\s*\(/i.test(sql)) {
    return res.status(400).json({ error: 'Consulta no permitida' });
  }

  let conn;
  try {
    conn = await pool.getConnection();
    await conn.query('SET SESSION MAX_EXECUTION_TIME=10000').catch(() => {});
    await conn.query('START TRANSACTION READ ONLY');
    const [rows] = await conn.query(sql, params);
    await conn.query('ROLLBACK');
    const list = Array.isArray(rows) ? rows : [rows];
    res.json({
      rowCount: list.length,
      truncated: list.length > MAX_ROWS_READ,
      rows: list.slice(0, MAX_ROWS_READ)
    });
  } catch (err) {
    if (conn) await conn.query('ROLLBACK').catch(() => {});
    res.status(400).json({ error: err.message });
  } finally {
    if (conn) conn.release();
  }
});

// ---------- Escritura ----------
// POST /api/claude/update
// {
//   "table": "EstadisticasBateoTemporada",
//   "where": { "id_jugador": 32, "id_temporada": 1 },
//   "set":   { "home_runs": 4 },
//   "maxRows": 1,          // opcional, default 1, máximo 50
//   "dryRun": true         // opcional: muestra antes/después sin guardar
// }
router.post('/update', async (req, res) => {
  const { table, where, set } = req.body || {};
  const dryRun = req.body?.dryRun === true;
  const maxRows = Math.min(Math.max(parseInt(req.body?.maxRows, 10) || 1, 1), 50);

  const editable = EDITABLE[table];
  if (!editable) {
    return res.status(400).json({ error: 'Tabla no permitida', allowed: Object.keys(EDITABLE) });
  }
  if (!where || typeof where !== 'object' || !Object.keys(where).length) {
    return res.status(400).json({ error: 'Falta "where"' });
  }
  if (!set || typeof set !== 'object' || !Object.keys(set).length) {
    return res.status(400).json({ error: 'Falta "set"' });
  }
  for (const [k, v] of Object.entries(where)) {
    if (!WHERE_COLS.includes(k)) return res.status(400).json({ error: `Columna no permitida en where: ${k}` });
    if (!Number.isInteger(v)) return res.status(400).json({ error: `Valor de where debe ser entero: ${k}` });
  }
  for (const [k, v] of Object.entries(set)) {
    if (!editable.includes(k)) return res.status(400).json({ error: `Columna no editable: ${k}`, editable });
    if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) {
      return res.status(400).json({ error: `Valor inválido para ${k}` });
    }
  }

  const whereSql = Object.keys(where).map(k => `\`${k}\` = ?`).join(' AND ');
  const whereVals = Object.values(where);
  const setSql = Object.keys(set).map(k => `\`${k}\` = ?`).join(', ');
  const setVals = Object.values(set);

  let conn;
  try {
    conn = await pool.getConnection();
    await conn.beginTransaction();

    const [before] = await conn.query(
      `SELECT * FROM \`${table}\` WHERE ${whereSql} FOR UPDATE`, whereVals
    );
    if (!before.length) {
      await conn.rollback();
      return res.status(404).json({ error: 'No hay filas con ese where' });
    }
    if (before.length > maxRows) {
      await conn.rollback();
      return res.status(400).json({ error: `El where coincide con ${before.length} filas (máximo ${maxRows})` });
    }

    const [result] = await conn.query(
      `UPDATE \`${table}\` SET ${setSql} WHERE ${whereSql}`, [...setVals, ...whereVals]
    );
    const [after] = await conn.query(`SELECT * FROM \`${table}\` WHERE ${whereSql}`, whereVals);

    if (dryRun) await conn.rollback();
    else await conn.commit();

    console.log(`[apiClaude] ${dryRun ? 'DRY-RUN' : 'UPDATE'} ${table} where=${JSON.stringify(where)} set=${JSON.stringify(set)} rows=${result.affectedRows}`);
    res.json({ dryRun, affectedRows: result.affectedRows, before, after });
  } catch (err) {
    if (conn) await conn.rollback().catch(() => {});
    res.status(400).json({ error: err.message });
  } finally {
    if (conn) conn.release();
  }
});

module.exports = router;
