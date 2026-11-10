// app.js
const express = require('express');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');

// === Carga entorno según NODE_ENV ===
const envFile = process.env.NODE_ENV === 'production'
  ? './env/.env'
  : './env/.env.local';
dotenv.config({ path: envFile });

// === Inicializa app ===
const app = express();
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// === Archivos estáticos ===
app.use('/resources', express.static(path.join(__dirname, 'public')));

// === Middlewares base ===
app.use(express.urlencoded({ extended: true }));
// La API de Claude manda lotes grandes (temporada completa); el resto usa el límite normal.
app.use('/api/claude', express.json({ limit: '2mb' }));
app.use(express.json());
app.use(cookieParser());

// === Sesión ===
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev',
  resave: false,
  saveUninitialized: false,
  cookie: {
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

// === Variables locales ===
app.use((req, res, next) => {
  res.locals.currentPath = req.path;
  res.locals.title = 'Academia ITSON';
  next();
});

// === Cargar middlewares y rutas ===
const { isAuthenticated } = require('./middlewares/auth');

// rutas principales
app.use('/', require('./Rutas/index'));
app.use('/adminGeneral', isAuthenticated, require('./Rutas/adminGeneral'));
app.use('/Coordinadores', require('./Rutas/coordinador'));
app.use('/adminEstadisticas', isAuthenticated, require('./Rutas/adminEstadisticas'));
app.use('/adminCoordinador', isAuthenticated, require('./Rutas/adminCoordinador'));

// API con token para que Claude corrija estadísticas (ver Rutas/apiClaude.js)
app.use('/api/claude', require('./Rutas/apiClaude'));

// === Health check local ===
app.get('/health', (_, res) => res.send('ok'));

// === Chequeo de conexión a BD (opcional) ===
const mysql = require('mysql2/promise');
app.get('/dbcheck', async (_, res) => {
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_DATABASE,
      port: process.env.DB_PORT || 3306
    });
    await connection.query('SELECT 1');
    await connection.end();
    res.send('DB connected');
  } catch (err) {
    console.error('DB check error:', err.message);
    res.status(500).send('DB connection failed');
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Internal Server Error');
});

// health checks opcionales
app.get('/health', (_, res) => res.send('ok'));

const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';
app.listen(PORT, HOST, () => console.log(`http://${HOST}:${PORT}`));

module.exports = app;



