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
//  - Escrituras: INSERT/UPDATE/DELETE solo en las tablas y columnas de
//    TABLES (estadísticas y armado de temporada: temporadas, equipos,
//    jugadores, asignaciones). WHERE solo por igualdad en columnas id,
//    límite de filas, antes/después, y todo en una transacción con dryRun.
//    Temporadas, Equipos, Entrenadores y Jugadores no se pueden borrar.

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

// Tablas que la API puede tocar.
//  - cols:   columnas que se pueden escribir (insert/update)
//  - where:  columnas enteras que se pueden usar en el WHERE (update/delete)
//  - insert / remove: si se permite insertar / borrar filas
//  - stats:  columnas numéricas que no pueden ser negativas
// UsuarioAdministradores nunca aparece aquí.
const STAT_BATEO = [
  'apariciones_al_bat', 'hits', 'bases_por_bolas', 'carreras',
  'carreras_producidas', 'sencillos', 'dobles', 'triples',
  'home_runs', 'bases_robadas'
];
const STAT_PITCHEO = [
  'bases_por_bolas', 'victorias', 'derrotas', 'entradas_lanzadas',
  'carreras_limpias', 'ponches'
];
const STAT_EQUIPO = [
  'carreras_en_contra', 'carreras_a_favor', 'ganados', 'perdidos',
  'empatados', 'errores'
];

const TABLES = {
  EstadisticasBateoTemporada: {
    cols: ['id_temporada', 'id_jugador', 'id_equipo_temporada', ...STAT_BATEO],
    where: ['id_estadistica', 'id_temporada', 'id_jugador', 'id_equipo_temporada'],
    stats: STAT_BATEO, insert: true, remove: true
  },
  EstadisticasPitcheoTemporada: {
    cols: ['id_temporada', 'id_jugador', 'id_equipo_temporada', ...STAT_PITCHEO],
    where: ['id_estadistica', 'id_temporada', 'id_jugador', 'id_equipo_temporada'],
    stats: STAT_PITCHEO, insert: true, remove: true
  },
  EstadisticasEquipoTemporada: {
    cols: ['id_temporada', 'id_equipo_temporada', ...STAT_EQUIPO],
    where: ['id_estadistica', 'id_temporada', 'id_equipo_temporada'],
    stats: STAT_EQUIPO, insert: true, remove: true
  },
  Temporadas: {
    cols: ['nombre', 'fecha_inicio', 'fecha_fin', 'fecha_corte_edad', 'is_activa'],
    where: ['id_temporada', 'is_activa'],
    insert: true, remove: false
  },
  CategoriaTemporadaRango: {
    cols: ['id_temporada', 'id_categoria', 'nacimiento_desde', 'nacimiento_hasta'],
    where: ['id', 'id_temporada', 'id_categoria'],
    insert: true, remove: true
  },
  MinimoAparicionesBateoTemporada: {
    cols: ['id_temporada', 'habilitado', 'min_apariciones'],
    where: ['id', 'id_temporada'],
    insert: true, remove: true
  },
  Equipos: {
    cols: ['nombre_corto'],
    where: ['id_equipo'],
    insert: true, remove: false
  },
  Entrenadores: {
    cols: ['nombres', 'apellido_paterno', 'apellido_materno'],
    where: ['id_entrenador'],
    insert: true, remove: false
  },
  Jugadores: {
    cols: ['url_foto', 'nombres', 'apellido_paterno', 'apellido_materno', 'fecha_nacimiento', 'activo'],
    where: ['id_jugador'],
    insert: true, remove: false
  },
  EquipoTemporada: {
    cols: ['id_equipo', 'id_temporada', 'id_categoria', 'nombre', 'colores', 'url_foto', 'id_entrenador'],
    where: ['id_equipo_temporada', 'id_equipo', 'id_temporada', 'id_categoria'],
    insert: true, remove: true
  },
  JugadorTemporadaCategoria: {
    cols: ['id_jugador', 'id_temporada', 'id_categoria', 'asignado_automatico'],
    where: ['id', 'id_jugador', 'id_temporada', 'id_categoria'],
    insert: true, remove: true
  },
  JugadorEquipoTemporada: {
    cols: ['id_jugador', 'id_equipo_temporada', 'fecha_alta', 'fecha_baja'],
    where: ['id', 'id_jugador', 'id_equipo_temporada'],
    insert: true, remove: true
  },
  CoordinadorTemporadaCategoria: {
    cols: ['id_coordinador', 'id_temporada', 'id_categoria'],
    where: ['id', 'id_coordinador', 'id_temporada', 'id_categoria'],
    insert: true, remove: true
  },
  UsuarioRolTemporadaCategoria: {
    cols: ['id_usuario', 'rol', 'id_temporada', 'id_categoria', 'alias'],
    where: ['id', 'id_usuario', 'id_temporada', 'id_categoria'],
    insert: true, remove: true
  }
};

const MAX_BATCH_OPS = 1000;
const MAX_ROWS_WRITE = 500;

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
// Validación común. Lanza Error con mensaje en español si algo no cuadra.
// refs: resultados de operaciones anteriores del batch ({ alias: insertId }).
function bad(msg) { const e = new Error(msg); e.userError = true; return e; }

function resolveValue(v, refs) {
  if (v && typeof v === 'object' && !Array.isArray(v) && typeof v.ref === 'string') {
    if (!(v.ref in refs)) throw bad(`Referencia desconocida: ${v.ref}`);
    return refs[v.ref];
  }
  return v;
}

function checkCols(table, obj, allowed, label, refs, { ints = false, stats = [] } = {}) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj) || !Object.keys(obj).length) {
    throw bad(`Falta "${label}"`);
  }
  const out = {};
  for (const [k, raw] of Object.entries(obj)) {
    if (!allowed.includes(k)) throw bad(`Columna no permitida en ${label} de ${table}: ${k}`);
    let v = resolveValue(raw, refs);
    if (typeof v === 'boolean') v = v ? 1 : 0;
    if (ints) {
      if (!Number.isInteger(v)) throw bad(`Valor de ${label} debe ser entero: ${k}`);
    } else if (v === null) {
      // ok
    } else if (typeof v === 'number') {
      if (!Number.isFinite(v)) throw bad(`Valor inválido para ${k}`);
      if (stats.includes(k) && v < 0) throw bad(`Valor negativo para ${k}`);
    } else if (typeof v === 'string') {
      if (v.length > 255) throw bad(`Texto demasiado largo en ${k}`);
      if (stats.includes(k)) throw bad(`Valor inválido para ${k}`);
    } else {
      throw bad(`Valor inválido para ${k}`);
    }
    out[k] = v;
  }
  return out;
}

function tableCfg(table, op) {
  const cfg = TABLES[table];
  if (!cfg) throw bad(`Tabla no permitida: ${table}`);
  if (op === 'insert' && !cfg.insert) throw bad(`No se permite insertar en ${table}`);
  if (op === 'delete' && !cfg.remove) throw bad(`No se permite borrar en ${table}`);
  return cfg;
}

const pkOf = t => ({
  Temporadas: 'id_temporada', Equipos: 'id_equipo', Entrenadores: 'id_entrenador',
  Jugadores: 'id_jugador', EquipoTemporada: 'id_equipo_temporada',
  EstadisticasBateoTemporada: 'id_estadistica', EstadisticasPitcheoTemporada: 'id_estadistica',
  EstadisticasEquipoTemporada: 'id_estadistica'
}[t] || 'id');

// Ejecuta una operación dentro de la conexión/transacción dada.
async function runOp(conn, op, refs) {
  const kind = op?.op;
  const table = op?.table;

  if (kind === 'insert') {
    const cfg = tableCfg(table, 'insert');
    const values = checkCols(table, op.values, cfg.cols, 'values', refs, { stats: cfg.stats || [] });
    const cols = Object.keys(values);
    const [r] = await conn.query(
      `INSERT INTO \`${table}\` (${cols.map(c => `\`${c}\``).join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`,
      Object.values(values)
    );
    const pk = pkOf(table);
    const [after] = await conn.query(`SELECT * FROM \`${table}\` WHERE \`${pk}\` = ?`, [r.insertId]);
    if (op.as) refs[String(op.as)] = r.insertId;
    return { op: 'insert', table, insertId: r.insertId, as: op.as, after: after[0] };
  }

  if (kind === 'update' || kind === 'delete') {
    const cfg = tableCfg(table, kind);
    const where = checkCols(table, op.where, cfg.where, 'where', refs, { ints: true });
    const maxRows = Math.min(Math.max(parseInt(op.maxRows, 10) || 1, 1), MAX_ROWS_WRITE);
    const whereSql = Object.keys(where).map(k => `\`${k}\` = ?`).join(' AND ');
    const whereVals = Object.values(where);

    const [before] = await conn.query(`SELECT * FROM \`${table}\` WHERE ${whereSql} FOR UPDATE`, whereVals);
    if (!before.length) {
      if (op.allowNone) return { op: kind, table, affectedRows: 0, before: [], after: [] };
      throw bad(`${table}: no hay filas con where ${JSON.stringify(where)}`);
    }
    if (before.length > maxRows) {
      throw bad(`${table}: el where coincide con ${before.length} filas (máximo ${maxRows}; usa "maxRows")`);
    }

    if (kind === 'delete') {
      const [r] = await conn.query(`DELETE FROM \`${table}\` WHERE ${whereSql}`, whereVals);
      return { op: 'delete', table, affectedRows: r.affectedRows, before, after: [] };
    }

    const set = checkCols(table, op.set, cfg.cols, 'set', refs, { stats: cfg.stats || [] });
    const setSql = Object.keys(set).map(k => `\`${k}\` = ?`).join(', ');
    const [r] = await conn.query(
      `UPDATE \`${table}\` SET ${setSql} WHERE ${whereSql}`, [...Object.values(set), ...whereVals]
    );
    // "después" por llave primaria: el where puede dejar de coincidir tras el update
    const pk = pkOf(table);
    const ids = before.map(r => r[pk]);
    const [after] = await conn.query(`SELECT * FROM \`${table}\` WHERE \`${pk}\` IN (?)`, [ids]);
    return { op: 'update', table, affectedRows: r.affectedRows, before, after };
  }

  throw bad(`Operación desconocida: ${kind} (usa insert, update o delete)`);
}

// Corre varias operaciones en UNA transacción. Si una falla, no se guarda nada.
async function runBatch(ops, dryRun) {
  const conn = await pool.getConnection();
  const refs = {};
  const results = [];
  try {
    await conn.beginTransaction();
    for (let i = 0; i < ops.length; i++) {
      try {
        results.push(await runOp(conn, ops[i], refs));
      } catch (err) {
        err.opIndex = i;
        throw err;
      }
    }
    if (dryRun) await conn.rollback();
    else await conn.commit();
    return { dryRun, ops: results.length, refs, results };
  } catch (err) {
    await conn.rollback().catch(() => {});
    throw err;
  } finally {
    conn.release();
  }
}

function sendError(res, err) {
  const body = { error: err.message };
  if (err.opIndex !== undefined) body.opIndex = err.opIndex;
  res.status(400).json(body);
}

// POST /api/claude/update   (una sola actualización; compatible con la versión anterior)
// {
//   "table": "EstadisticasBateoTemporada",
//   "where": { "id_jugador": 32, "id_temporada": 1 },
//   "set":   { "home_runs": 4 },
//   "maxRows": 1,          // opcional, default 1
//   "dryRun": true         // opcional: muestra antes/después sin guardar
// }
router.post('/update', async (req, res) => {
  const { table, where, set, maxRows } = req.body || {};
  const dryRun = req.body?.dryRun === true;
  try {
    const out = await runBatch([{ op: 'update', table, where, set, maxRows }], dryRun);
    const r = out.results[0];
    console.log(`[apiClaude] ${dryRun ? 'DRY-RUN' : 'UPDATE'} ${table} where=${JSON.stringify(where)} set=${JSON.stringify(set)} rows=${r.affectedRows}`);
    res.json({ dryRun, affectedRows: r.affectedRows, before: r.before, after: r.after });
  } catch (err) {
    sendError(res, err);
  }
});

// POST /api/claude/batch
// Varias operaciones en una sola transacción (todo o nada). Sirve para crear
// una temporada nueva con sus categorías, equipos y jugadores.
// {
//   "dryRun": true,
//   "ops": [
//     { "op": "insert", "table": "Temporadas", "as": "t",
//       "values": { "nombre": "2026", "fecha_inicio": "2026-02-01", ... } },
//     { "op": "insert", "table": "EquipoTemporada", "as": "eq1",
//       "values": { "id_temporada": { "ref": "t" }, "id_categoria": 3, "nombre": "Potros" } },
//     { "op": "update", "table": "Temporadas", "where": { "id_temporada": 1 }, "set": { "is_activa": 0 } },
//     { "op": "delete", "table": "JugadorEquipoTemporada", "where": { "id": 99 } }
//   ]
// }
// { "ref": "alias" } se reemplaza por el id insertado en la operación con "as": "alias".
router.post('/batch', async (req, res) => {
  const ops = req.body?.ops;
  const dryRun = req.body?.dryRun === true;
  if (!Array.isArray(ops) || !ops.length) return res.status(400).json({ error: 'Falta "ops"' });
  if (ops.length > MAX_BATCH_OPS) return res.status(400).json({ error: `Máximo ${MAX_BATCH_OPS} operaciones` });
  try {
    const out = await runBatch(ops, dryRun);
    const count = out.results.reduce((m, r) => (m[`${r.op} ${r.table}`] = (m[`${r.op} ${r.table}`] || 0) + 1, m), {});
    console.log(`[apiClaude] ${dryRun ? 'DRY-RUN' : 'BATCH'} ${JSON.stringify(count)}`);
    res.json({ ...out, summary: count });
  } catch (err) {
    sendError(res, err);
  }
});

module.exports = router;
