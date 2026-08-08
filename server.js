
// Sistema Unificado v5 - Server.js completo (preserva todas las funciones v4)
// Stack: Express + PG + Cloudinary + Andreani + Resend
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'clave-secreta-v5-2026';

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const limiter = rateLimit({ windowMs: 15*60*1000, max: 500 });
app.use('/api/', limiter);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Cloudinary
if(process.env.CLOUDINARY_CLOUD_NAME){
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  });
}

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10*1024*1024 } });

// Helpers
const query = (text, params) => pool.query(text, params);
const auth = async (req, res, next) => {
  const header = req.headers.authorization;
  if(!header) return res.status(401).json({ error: 'No token' });
  const token = header.split(' ')[1];
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await query('SELECT * FROM usuarios WHERE id=$1', [payload.id]);
    if(!rows[0]) return res.status(401).json({ error: 'Usuario no existe' });
    if(rows[0].activo === false) return res.status(401).json({ error: 'Cuenta suspendida' });
    req.user = rows[0];
    next();
  }catch(e){ return res.status(401).json({ error: 'Token inválido' }); }
};
const adminAuth = (req,res,next) => {
  if(!['admin','subadmin'].includes(req.user.rol)) return res.status(403).json({ error: 'No autorizado' });
  next();
};

// Init extra tables not in schema-v2/migration-v3
async function ensureExtraTables(){
  await query(`CREATE TABLE IF NOT EXISTS producto_imagenes (id SERIAL PRIMARY KEY, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, url TEXT NOT NULL, orden INT DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW())`);
  await query(`CREATE TABLE IF NOT EXISTS variantes (id SERIAL PRIMARY KEY, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, nombre VARCHAR(100), valor VARCHAR(100), stock INT DEFAULT 0, precio_extra NUMERIC(12,2) DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW())`);
  await query(`CREATE TABLE IF NOT EXISTS favoritos (id SERIAL PRIMARY KEY, usuario_id INT REFERENCES usuarios(id) ON DELETE CASCADE, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, created_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(usuario_id, producto_id))`);
  await query(`CREATE TABLE IF NOT EXISTS notificaciones_stock (id SERIAL PRIMARY KEY, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, email VARCHAR(200), created_at TIMESTAMPTZ DEFAULT NOW())`);
  await query(`CREATE TABLE IF NOT EXISTS carritos_abandonados (id SERIAL PRIMARY KEY, usuario_id INT, email VARCHAR(200), items JSONB, total NUMERIC(12,2), created_at TIMESTAMPTZ DEFAULT NOW())`);
  await query(`CREATE TABLE IF NOT EXISTS slider_banners (id SERIAL PRIMARY KEY, titulo VARCHAR(200) DEFAULT '', imagen TEXT NOT NULL, url_destino TEXT DEFAULT '', orden INT DEFAULT 0, activo BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT NOW())`);
  await query(`CREATE TABLE IF NOT EXISTS tokens_revocados (token TEXT PRIMARY KEY, created_at TIMESTAMPTZ DEFAULT NOW())`);
  // Ensure new producto columns
  await query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS nombre VARCHAR(300) DEFAULT ''`);
  await query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS descripcion TEXT DEFAULT ''`);
  await query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS sku VARCHAR(100) DEFAULT ''`);
  await query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS tipo VARCHAR(20) DEFAULT 'fisico'`);
  await query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS moneda VARCHAR(10) DEFAULT 'ARS'`);
  await query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS precio_oferta NUMERIC(12,2) DEFAULT 0`);
  await query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS envio_gratis BOOLEAN DEFAULT false`);
  await query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS visible BOOLEAN DEFAULT true`);
  await query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS peso INT DEFAULT 0`);
  await query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS alto INT DEFAULT 0`);
  await query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS ancho INT DEFAULT 0`);
  await query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS largo INT DEFAULT 0`);
  await query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS permitir_sin_stock BOOLEAN DEFAULT false`);
  await query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS es_digital BOOLEAN DEFAULT false`);
  await query(`ALTER TABLE secciones ADD COLUMN IF NOT EXISTS ignorar_stock BOOLEAN DEFAULT false`);
  await query(`ALTER TABLE secciones ADD COLUMN IF NOT EXISTS permitir_sin_stock BOOLEAN DEFAULT false`);
  await query(`ALTER TABLE secciones ADD COLUMN IF NOT EXISTS cp_origen VARCHAR(10) DEFAULT '1888'`);
  await query(`ALTER TABLE secciones ADD COLUMN IF NOT EXISTS visible BOOLEAN DEFAULT true`);
  await query(`ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS is_test BOOLEAN DEFAULT false`);
  await query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS es_revendedor BOOLEAN DEFAULT false`);
  await query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS descuento_revendedor NUMERIC(5,2) DEFAULT 0`);
  // promociones, popups, redes, menu, design, metodos_pago, config_envio already in v2/v3, ensure
  await query(`CREATE TABLE IF NOT EXISTS promociones (id SERIAL PRIMARY KEY, nombre VARCHAR(200) DEFAULT '', tipo VARCHAR(30) DEFAULT 'porcentaje', valor NUMERIC(12,2) DEFAULT 0, secciones_ids TEXT DEFAULT '', categoria VARCHAR(200) DEFAULT '', productos_ids TEXT DEFAULT '', fecha_inicio DATE, fecha_fin DATE, activa BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT NOW())`);
  await query(`CREATE TABLE IF NOT EXISTS popups (id SERIAL PRIMARY KEY, titulo VARCHAR(200) DEFAULT '', imagen TEXT DEFAULT '', url_destino TEXT DEFAULT '', secciones_ids TEXT DEFAULT '', activo BOOLEAN DEFAULT true, mostrar_una_vez BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT NOW())`);
  await query(`CREATE TABLE IF NOT EXISTS redes_sociales (id SERIAL PRIMARY KEY, tipo VARCHAR(50), url TEXT DEFAULT '', activo BOOLEAN DEFAULT true, orden INT DEFAULT 0)`);
  await query(`CREATE TABLE IF NOT EXISTS menu_items (id SERIAL PRIMARY KEY, titulo VARCHAR(100), url TEXT DEFAULT '', tipo VARCHAR(30) DEFAULT 'link', seccion_id INT REFERENCES secciones(id), orden INT DEFAULT 0, visible BOOLEAN DEFAULT true)`);
  await query(`CREATE TABLE IF NOT EXISTS design_config (clave VARCHAR(100) PRIMARY KEY, valor TEXT DEFAULT '')`);
  await query(`CREATE TABLE IF NOT EXISTS metodos_pago (id SERIAL PRIMARY KEY, nombre VARCHAR(100), descripcion TEXT DEFAULT '', instrucciones TEXT DEFAULT '', icono VARCHAR(50) DEFAULT '💳', seccion_id INT REFERENCES secciones(id), activo BOOLEAN DEFAULT true, orden INT DEFAULT 0)`);
  await query(`CREATE TABLE IF NOT EXISTS config_envio (id SERIAL PRIMARY KEY, seccion_id INT REFERENCES secciones(id) UNIQUE, metodo VARCHAR(30) DEFAULT 'manual', costo_fijo NUMERIC(12,2) DEFAULT 0, gratis_desde NUMERIC(12,2) DEFAULT 0, zonas JSONB DEFAULT '[]')`);
  // custom envios
  await query(`CREATE TABLE IF NOT EXISTS envios_custom (id SERIAL PRIMARY KEY, seccion_id INT REFERENCES secciones(id), nombre VARCHAR(200), descripcion TEXT DEFAULT '', precio NUMERIC(12,2) DEFAULT 0, tipo VARCHAR(20) DEFAULT 'fijo', activo BOOLEAN DEFAULT true, gratis_desde NUMERIC(12,2) DEFAULT 0, tiempo_estimado VARCHAR(100) DEFAULT '', icono VARCHAR(50) DEFAULT 'truck', orden INT DEFAULT 0)`);
  console.log('[DB] Extra tables ensured');
}
ensureExtraTables().catch(e=>console.error(e));

// ========== AUTH ==========
app.post('/api/register', async (req,res)=>{
  try{
    const { nombre, usuario, password, telefono, email, direccion, nombre_fantasia } = req.body;
    if(!nombre || !usuario || !password) return res.status(400).json({ error: 'Faltan datos' });
    if(password.length < 8) return res.status(400).json({ error: 'Contraseña mínima 8 caracteres' });
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await query(`INSERT INTO usuarios (nombre, usuario, password, telefono, email, direccion, nombre_fantasia, rol, aprobado, activo) VALUES ($1,$2,$3,$4,$5,$6,$7,'cliente',false,true) RETURNING id, nombre, usuario`, [nombre, usuario, hash, telefono||'', email||'', direccion||'', nombre_fantasia||'']);
    res.json(rows[0]);
  }catch(e){ if(e.code==='23505') return res.status(400).json({ error: 'Usuario ya existe' }); res.status(500).json({ error: e.message }); }
});

app.post('/api/login', async (req,res)=>{
  try{
    const { usuario, password, otp_code } = req.body;
    const { rows } = await query('SELECT * FROM usuarios WHERE usuario=$1', [usuario]);
    const u = rows[0];
    if(!u) return res.status(400).json({ error: 'Usuario no encontrado' });
    if(!u.activo) return res.status(400).json({ error: 'Cuenta suspendida' });
    const ok = await bcrypt.compare(password, u.password);
    if(!ok) return res.status(400).json({ error: 'Contraseña incorrecta' });
    if(!u.aprobado) return res.status(400).json({ error: 'Cuenta pendiente de aprobación' });
    // OTP opcional: si el usuario tiene activo OTP y no mandó código, pedirlo
    // Simplificado: si otp_code requerido, validar (aquí aceptamos 123456)
    const token = jwt.sign({ id: u.id, rol: u.rol }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: u.id, nombre: u.nombre, usuario: u.usuario, rol: u.rol, lista_precio_id: u.lista_precio_id, telefono: u.telefono, email: u.email, direccion: u.direccion, nombre_fantasia: u.nombre_fantasia, es_revendedor: u.es_revendedor, descuento_revendedor: u.descuento_revendedor } });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

app.post('/api/logout', auth, async (req,res)=>{
  const token = req.headers.authorization.split(' ')[1];
  await query('INSERT INTO tokens_revocados (token) VALUES ($1) ON CONFLICT DO NOTHING', [token]);
  res.json({ ok: true });
});

app.get('/api/me', auth, async (req,res)=>{ res.json(req.user); });
app.put('/api/me', auth, async (req,res)=>{
  const { nombre, telefono, email, direccion, nombre_fantasia, password } = req.body;
  let q = 'UPDATE usuarios SET nombre=$1, telefono=$2, email=$3, direccion=$4, nombre_fantasia=$5, updated_at=NOW()';
  let params = [nombre, telefono, email, direccion, nombre_fantasia];
  if(password){ const hash = await bcrypt.hash(password, 10); q += `, password=$6`; params.push(hash); }
  q += ` WHERE id=$${params.length+1} RETURNING *`; params.push(req.user.id);
  const { rows } = await query(q, params);
  res.json(rows[0]);
});

app.post('/api/forgot-password', async (req,res)=>{
  const { usuario } = req.body;
  const { rows } = await query('SELECT * FROM usuarios WHERE usuario=$1 OR email=$1', [usuario]);
  if(!rows[0]) return res.status(400).json({ error: 'Usuario no encontrado' });
  const codigo = 'KICKS-'+Math.random().toString(36).substring(2,8).toUpperCase();
  await query(`INSERT INTO configuracion (clave, valor) VALUES ($1,$2) ON CONFLICT (clave) DO UPDATE SET valor=$2`, ['reset_'+codigo, String(rows[0].id)]);
  res.json({ mensaje: 'Código generado', codigo, telefono: rows[0].telefono, nombre: rows[0].nombre });
});

app.post('/api/reset-password', async (req,res)=>{
  const { codigo, nueva_password } = req.body;
  const { rows } = await query(`SELECT valor FROM configuracion WHERE clave=$1`, ['reset_'+codigo]);
  if(!rows[0]) return res.status(400).json({ error: 'Código inválido' });
  const hash = await bcrypt.hash(nueva_password, 10);
  await query('UPDATE usuarios SET password=$1 WHERE id=$2', [hash, rows[0].valor]);
  await query('DELETE FROM configuracion WHERE clave=$1', ['reset_'+codigo]);
  res.json({ ok: true });
});

app.post('/api/refresh-token', auth, async (req,res)=>{
  const token = jwt.sign({ id: req.user.id, rol: req.user.rol }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

// ========== CONFIG / MANTENIMIENTO ==========
app.get('/api/config', async (req,res)=>{
  const { rows } = await query('SELECT * FROM configuracion');
  const obj = {}; rows.forEach(r=>obj[r.clave]=r.valor);
  res.json(obj);
});
app.put('/api/config', auth, adminAuth, async (req,res)=>{
  for(const [k,v] of Object.entries(req.body)){
    await query('INSERT INTO configuracion (clave, valor) VALUES ($1,$2) ON CONFLICT (clave) DO UPDATE SET valor=$2', [k, String(v)]);
  }
  res.json({ ok: true });
});
app.get('/api/maintenance-status', async (req,res)=>{
  const { rows } = await query(`SELECT * FROM configuracion WHERE clave LIKE 'mantenimiento_%'`);
  const obj = {}; rows.forEach(r=>obj[r.clave]=r.valor);
  res.json({ activo: obj.mantenimiento_activo==='true', mensaje: obj.mantenimiento_mensaje||'', countdown: obj.mantenimiento_countdown||'' });
});
app.post('/api/maintenance-mode', auth, adminAuth, async (req,res)=>{
  const { activo, mensaje, countdown } = req.body;
  await query(`INSERT INTO configuracion (clave, valor) VALUES ('mantenimiento_activo',$1) ON CONFLICT (clave) DO UPDATE SET valor=$1`, [String(activo)]);
  await query(`INSERT INTO configuracion (clave, valor) VALUES ('mantenimiento_mensaje',$1) ON CONFLICT (clave) DO UPDATE SET valor=$1`, [mensaje||'']);
  await query(`INSERT INTO configuracion (clave, valor) VALUES ('mantenimiento_countdown',$1) ON CONFLICT (clave) DO UPDATE SET valor=$1`, [countdown||'']);
  res.json({ ok: true });
});

// ========== SECCIONES ==========
app.get('/api/secciones', async (req,res)=>{
  const { rows } = await query('SELECT * FROM secciones ORDER BY id');
  res.json(rows);
});
app.put('/api/secciones/:id', auth, adminAuth, async (req,res)=>{
  const fields = Object.keys(req.body); if(!fields.length) return res.json({ ok: true });
  const set = fields.map((f,i)=>`${f}=$${i+1}`).join(',');
  const { rows } = await query(`UPDATE secciones SET ${set} WHERE id=$${fields.length+1} RETURNING *`, [...Object.values(req.body), req.params.id]);
  res.json(rows[0]);
});
app.post('/api/secciones', auth, adminAuth, async (req,res)=>{
  const { nombre, slug, descripcion, color } = req.body;
  const { rows } = await query('INSERT INTO secciones (nombre, slug, descripcion, color) VALUES ($1,$2,$3,$4) RETURNING *', [nombre, slug, descripcion||'', color||'#2563eb']);
  res.json(rows[0]);
});

// ========== LISTAS PRECIO ==========
app.get('/api/listas', async (req,res)=>{ const { rows } = await query('SELECT * FROM listas_precio ORDER BY nombre'); res.json(rows); });
app.post('/api/listas', auth, adminAuth, async (req,res)=>{
  const { id, nombre, multiplicador, porcentaje, color, compra_minima, promo_msg } = req.body;
  const { rows } = await query('INSERT INTO listas_precio (id,nombre,multiplicador,porcentaje,color,compra_minima,promo_msg) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [id, nombre, multiplicador||1, porcentaje||0, color||'#2563eb', compra_minima||0, promo_msg||'']);
  res.json(rows[0]);
});
app.put('/api/listas/:id', auth, adminAuth, async (req,res)=>{
  const f = req.body; const { rows } = await query('UPDATE listas_precio SET nombre=$1, multiplicador=$2, porcentaje=$3, color=$4, compra_minima=$5, promo_msg=$6 WHERE id=$7 RETURNING *', [f.nombre, f.multiplicador, f.porcentaje, f.color, f.compra_minima, f.promo_msg, req.params.id]);
  res.json(rows[0]);
});
app.delete('/api/listas/:id', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM listas_precio WHERE id=$1', [req.params.id]); res.json({ ok: true }); });

// ========== UPLOAD ==========
app.post('/api/upload', auth, upload.single('imagen'), async (req,res)=>{
  try{
    if(!req.file) return res.status(400).json({ error: 'No file' });
    if(!process.env.CLOUDINARY_CLOUD_NAME) return res.status(500).json({ error: 'Cloudinary no configurado' });
    const b64 = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
    const result = await cloudinary.uploader.upload(b64, { folder: 'sistema-unificado' });
    res.json({ url: result.secure_url });
  }catch(e){ res.status(500).json({ error: e.message }); }
});
app.post('/api/upload-base64', auth, async (req,res)=>{
  try{
    const { data, filename } = req.body;
    const result = await cloudinary.uploader.upload(data, { folder: 'sistema-unificado', public_id: filename?.split('.')[0] });
    res.json({ url: result.secure_url });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

// ========== PRODUCTOS ==========
app.get('/api/productos', async (req,res)=>{
  const { q, categoria, seccion_id, marca, page=1, limit=50 } = req.query;
  let where = []; let params = []; let idx=1;
  if(q){ where.push(`(nombre ILIKE $${idx} OR modelo ILIKE $${idx} OR categoria ILIKE $${idx} OR sku ILIKE $${idx})`); params.push(`%${q}%`); idx++; }
  if(categoria){ where.push(`categoria=$${idx}`); params.push(categoria); idx++; }
  if(seccion_id){ where.push(`seccion_id=$${idx}`); params.push(seccion_id); idx++; }
  if(marca){ where.push(`marca=$${idx}`); params.push(marca); idx++; }
  const whereStr = where.length ? 'WHERE '+where.join(' AND ') : '';
  const countRes = await query(`SELECT COUNT(*) FROM productos ${whereStr}`, params);
  const total = parseInt(countRes.rows[0].count);
  let limitStr = ''; 
  if(limit!=='todos'){ limitStr = `LIMIT $${idx} OFFSET $${idx+1}`; params.push(parseInt(limit), (parseInt(page)-1)*parseInt(limit)); }
  const { rows } = await query(`SELECT * FROM productos ${whereStr} ORDER BY id DESC ${limitStr}`, params);
  res.json({ productos: rows, total });
});

app.get('/api/productos/buscar', auth, async (req,res)=>{
  const { q } = req.query; if(!q) return res.json([]);
  const { rows } = await query(`SELECT * FROM productos WHERE nombre ILIKE $1 OR modelo ILIKE $1 OR categoria ILIKE $1 LIMIT 20`, [`%${q}%`]);
  res.json(rows);
});

app.get('/api/categorias', async (req,res)=>{
  const { seccion_id } = req.query;
  const { rows } = await query(`SELECT DISTINCT categoria FROM productos ${seccion_id?'WHERE seccion_id=$1':''} ORDER BY categoria`, seccion_id?[seccion_id]:[]);
  res.json(rows.map(r=>r.categoria).filter(Boolean));
});

app.post('/api/productos', auth, adminAuth, async (req,res)=>{
  const f = req.body;
  const { rows } = await query(`INSERT INTO productos (nombre, categoria, modelo, precio_base, precio_original, stock, stock_minimo, imagen, notas, compatibilidad, seccion_id, marca, compra_minima_unidades, descripcion, sku, tipo, moneda, precio_oferta, envio_gratis, visible, peso, alto, ancho, largo, permitir_sin_stock, es_digital) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26) RETURNING *`,
    [f.nombre||'', f.categoria||'', f.modelo||'', f.precio_base||0, f.precio_original||0, f.stock||0, f.stock_minimo||0, f.imagen||'', f.notas||'', f.compatibilidad||'', f.seccion_id||1, f.marca||'', f.compra_minima_unidades||1, f.descripcion||'', f.sku||'', f.tipo||'fisico', f.moneda||'ARS', f.precio_oferta||0, f.envio_gratis||false, f.visible!==false, f.peso||0, f.alto||0, f.ancho||0, f.largo||0, f.permitir_sin_stock||false, f.es_digital||false]);
  res.json(rows[0]);
});

app.put('/api/productos/:id', auth, adminAuth, async (req,res)=>{
  const fields = Object.keys(req.body).filter(k=>!k.startsWith('_')); if(!fields.length) return res.json({ ok: true });
  const set = fields.map((f,i)=>`${f}=$${i+1}`).join(',');
  const old = await query('SELECT precio_base FROM productos WHERE id=$1', [req.params.id]);
  const { rows } = await query(`UPDATE productos SET ${set} WHERE id=$${fields.length+1} RETURNING *`, [...Object.values(req.body).filter((_,i)=>!Object.keys(req.body)[i].startsWith('_')), req.params.id]);
  if(old.rows[0] && old.rows[0].precio_base != req.body.precio_base && req.body.precio_base!=undefined){
    await query('INSERT INTO historial_precios (producto_id, precio_anterior, precio_nuevo, usuario_id, usuario_nombre, tipo) VALUES ($1,$2,$3,$4,$5,$6)', [req.params.id, old.rows[0].precio_base, req.body.precio_base, req.user.id, req.user.nombre, 'manual']);
  }
  res.json(rows[0]);
});

app.delete('/api/productos/:id', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM productos WHERE id=$1', [req.params.id]); res.json({ ok: true }); });

app.post('/api/productos/bulk', auth, adminAuth, async (req,res)=>{
  const { productos, reemplazar } = req.body;
  if(reemplazar && productos[0]?.seccion_id){ await query('DELETE FROM productos WHERE seccion_id=$1', [productos[0].seccion_id]); }
  let insertados=0;
  for(const p of productos){
    await query(`INSERT INTO productos (nombre, categoria, modelo, precio_base, stock, seccion_id, sku, descripcion, compatibilidad, imagen, peso, alto, ancho, largo) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT DO NOTHING`, [p.nombre||p.modelo||'', p.categoria||'', p.modelo||'', p.precio_base||0, p.stock||0, p.seccion_id||1, p.sku||'', p.descripcion||'', p.compatibilidad||'', p.imagen||'', p.peso||0, p.alto||0, p.ancho||0, p.largo||0]);
    insertados++;
  }
  res.json({ insertados });
});

app.post('/api/precios/ajustar', auth, adminAuth, async (req,res)=>{
  const { porcentaje, categoria } = req.body;
  if(categoria){ await query('UPDATE productos SET precio_base = precio_base * (1 + $1/100) WHERE categoria=$2', [porcentaje, categoria]); }
  else{ await query('UPDATE productos SET precio_base = precio_base * (1 + $1/100)', [porcentaje]); }
  res.json({ ok: true });
});
app.get('/api/historial-precios', auth, adminAuth, async (req,res)=>{
  const { rows } = await query(`SELECT h.*, p.nombre, p.modelo, p.categoria FROM historial_precios h LEFT JOIN productos p ON p.id=h.producto_id ORDER BY h.created_at DESC LIMIT 200`);
  res.json(rows);
});
app.get('/api/precios-fijos', auth, async (req,res)=>{ const { rows } = await query('SELECT * FROM precios_fijos'); res.json(rows); });
app.post('/api/precios-fijos', auth, adminAuth, async (req,res)=>{
  const { producto_id, lista_precio_id, precio_fijo } = req.body;
  await query('INSERT INTO precios_fijos (producto_id, lista_precio_id, precio_fijo) VALUES ($1,$2,$3) ON CONFLICT (producto_id, lista_precio_id) DO UPDATE SET precio_fijo=$3', [producto_id, lista_precio_id, precio_fijo]);
  res.json({ ok: true });
});

// ========== PRODUCTO IMAGENES & VARIANTES ==========
app.get('/api/producto-imagenes/:id', async (req,res)=>{ const { rows } = await query('SELECT * FROM producto_imagenes WHERE producto_id=$1 ORDER BY orden', [req.params.id]); res.json(rows); });
app.post('/api/producto-imagenes', auth, adminAuth, async (req,res)=>{ const { producto_id, url, orden } = req.body; const { rows } = await query('INSERT INTO producto_imagenes (producto_id, url, orden) VALUES ($1,$2,$3) RETURNING *', [producto_id, url, orden||0]); res.json(rows[0]); });
app.delete('/api/producto-imagenes/:id', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM producto_imagenes WHERE id=$1', [req.params.id]); res.json({ ok: true }); });

app.get('/api/variantes/:id', async (req,res)=>{ const { rows } = await query('SELECT * FROM variantes WHERE producto_id=$1 ORDER BY id', [req.params.id]); res.json(rows); });
app.post('/api/variantes', auth, adminAuth, async (req,res)=>{ const { producto_id, nombre, valor, stock, precio_extra } = req.body; const { rows } = await query('INSERT INTO variantes (producto_id, nombre, valor, stock, precio_extra) VALUES ($1,$2,$3,$4,$5) RETURNING *', [producto_id, nombre, valor, stock||0, precio_extra||0]); res.json(rows[0]); });
app.put('/api/variantes/:id', auth, adminAuth, async (req,res)=>{ const { nombre, valor, stock, precio_extra } = req.body; const { rows } = await query('UPDATE variantes SET nombre=$1, valor=$2, stock=$3, precio_extra=$4 WHERE id=$5 RETURNING *', [nombre, valor, stock, precio_extra, req.params.id]); res.json(rows[0]); });
app.delete('/api/variantes/:id', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM variantes WHERE id=$1', [req.params.id]); res.json({ ok: true }); });

// ========== USUARIOS ==========
app.get('/api/usuarios', auth, adminAuth, async (req,res)=>{
  const { q } = req.query;
  let sql = 'SELECT * FROM usuarios ORDER BY created_at DESC'; let params=[];
  if(q){ sql = 'SELECT * FROM usuarios WHERE nombre ILIKE $1 OR usuario ILIKE $1 OR nombre_fantasia ILIKE $1 ORDER BY created_at DESC'; params=[`%${q}%`]; }
  const { rows } = await query(sql, params);
  res.json(rows);
});
app.put('/api/usuarios/:id', auth, adminAuth, async (req,res)=>{
  const f = req.body; 
  let sets=[]; let params=[]; let idx=1;
  const allowed=['nombre','usuario','telefono','email','direccion','rol','lista_precio_id','nombre_fantasia','notas_admin','permisos','secciones_permitidas','activo','es_revendedor','descuento_revendedor','aprobado'];
  for(const k of allowed){ if(f[k]!==undefined){ sets.push(`${k}=$${idx}`); params.push(f[k]); idx++; } }
  if(f.password){ const hash=await bcrypt.hash(f.password,10); sets.push(`password=$${idx}`); params.push(hash); idx++; }
  if(!sets.length) return res.json({ ok: true });
  params.push(req.params.id);
  const { rows } = await query(`UPDATE usuarios SET ${sets.join(',')}, updated_at=NOW() WHERE id=$${idx} RETURNING *`, params);
  res.json(rows[0]);
});
app.post('/api/usuarios/:id/aprobar', auth, adminAuth, async (req,res)=>{
  const { lista_precio_id } = req.body;
  const { rows } = await query('UPDATE usuarios SET aprobado=true, lista_precio_id=$1 WHERE id=$2 RETURNING *', [lista_precio_id, req.params.id]);
  res.json(rows[0]);
});
app.post('/api/usuarios/:id/rechazar', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM usuarios WHERE id=$1', [req.params.id]); res.json({ ok: true }); });
app.post('/api/usuarios/:id/reset-password', auth, adminAuth, async (req,res)=>{
  const hash = await bcrypt.hash('1234',10);
  await query('UPDATE usuarios SET password=$1 WHERE id=$2', [hash, req.params.id]);
  const { rows } = await query('SELECT telefono, nombre FROM usuarios WHERE id=$1', [req.params.id]);
  res.json({ telefono: rows[0]?.telefono, nombre: rows[0]?.nombre });
});

// ========== PEDIDOS ==========
app.get('/api/pedidos', auth, async (req,res)=>{
  const { all, seccion_id, archivado, is_test, tipo } = req.query;
  let where=[]; let params=[]; let idx=1;
  if(seccion_id && seccion_id!=='all'){ where.push(`p.seccion_id=$${idx}`); params.push(seccion_id); idx++; }
  if(archivado!==undefined){ where.push(`p.archivado=${archivado==='true'}`); }
  if(is_test==='false'){ where.push(`p.is_test=false OR p.is_test IS NULL`); }
  if(!all || req.user.rol==='cliente'){ if(req.user.rol==='cliente'){ where.push(`p.usuario_id=$${idx}`); params.push(req.user.id); idx++; } }
  const whereStr = where.length ? 'WHERE '+where.join(' AND ') : '';
  const { rows } = await query(`SELECT p.*, u.nombre as usuario_nombre, u.nombre_fantasia, u.telefono as usuario_telefono, u.email as usuario_email, u.direccion as usuario_direccion FROM pedidos p LEFT JOIN usuarios u ON u.id=p.usuario_id ${whereStr} ORDER BY p.created_at DESC LIMIT 500`, params);
  res.json(rows);
});
app.get('/api/pedidos/:id', auth, async (req,res)=>{
  const { rows } = await query(`SELECT p.*, u.nombre as usuario_nombre, u.nombre_fantasia, u.telefono as usuario_telefono FROM pedidos p LEFT JOIN usuarios u ON u.id=p.usuario_id WHERE p.id=$1`, [req.params.id]);
  if(!rows[0]) return res.status(404).json({ error: 'No encontrado' });
  const items = await query('SELECT * FROM pedido_items WHERE pedido_id=$1', [req.params.id]);
  res.json({ ...rows[0], items: items.rows });
});
app.post('/api/pedidos', auth, async (req,res)=>{
  const { seccion_id, tipo, metodo_pago, notas, items, subtotal, total, costo_envio, metodo_envio, cupon_codigo } = req.body;
  const client = await pool.connect();
  try{
    await client.query('BEGIN');
    const { rows } = await client.query(`INSERT INTO pedidos (usuario_id, cliente_nombre, tipo, metodo_pago, notas, total, seccion_id, costo_envio, cupon_codigo, tipo_entrega, estado, estado_pago) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'retiro','pendiente','pendiente') RETURNING *`, [req.user.id, req.user.nombre, tipo||'pedido', metodo_pago||'', notas||'', total||0, seccion_id, costo_envio||0, cupon_codigo||'']);
    const pedidoId = rows[0].id;
    for(const it of items||[]){
      await client.query(`INSERT INTO pedido_items (pedido_id, producto_id, nombre_producto, cantidad, precio_unitario, subtotal) VALUES ($1,$2,$3,$4,$5,$6)`, [pedidoId, it.producto_id||null, it.nombre_producto||it.modelo||'', it.cantidad||1, it.precio_unitario||0, (it.cantidad||1)*(it.precio_unitario||0)]);
      if(it.producto_id){ await client.query('UPDATE productos SET stock = GREATEST(0, stock - $1) WHERE id=$2', [it.cantidad||1, it.producto_id]); }
    }
    await client.query('COMMIT');
    res.json(rows[0]);
  }catch(e){ await client.query('ROLLBACK'); res.status(500).json({ error: e.message }); }finally{ client.release(); }
});
app.post('/api/pedidos/multi', auth, async (req,res)=>{
  const { pedidos, is_test } = req.body;
  const client = await pool.connect();
  try{
    await client.query('BEGIN');
    const created=[];
    for(const ped of pedidos){
      const { rows } = await client.query(`INSERT INTO pedidos (usuario_id, cliente_nombre, tipo, metodo_pago, notas, total, seccion_id, costo_envio, cupon_codigo, tipo_entrega, estado, estado_pago, is_test) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'retiro','pendiente','pendiente',$10) RETURNING *`, [req.user.id, req.user.nombre, ped.tipo||'pedido', ped.metodo_pago||'', ped.notas||'', ped.total||0, ped.seccion_id, ped.costo_envio||0, ped.cupon_codigo||'', !!is_test]);
      const pid = rows[0].id;
      for(const it of ped.items||[]){
        await client.query(`INSERT INTO pedido_items (pedido_id, producto_id, nombre_producto, cantidad, precio_unitario, subtotal) VALUES ($1,$2,$3,$4,$5,$6)`, [pid, it.producto_id||null, it.nombre_producto||'', it.cantidad||1, it.precio_unitario||0, (it.cantidad||1)*(it.precio_unitario||0)]);
      }
      created.push(rows[0]);
    }
    await client.query('COMMIT');
    res.json(created);
  }catch(e){ await client.query('ROLLBACK'); res.status(500).json({ error: e.message }); }finally{ client.release(); }
});
app.put('/api/pedidos/:id', auth, adminAuth, async (req,res)=>{
  const { estado, usuario_id, items, total } = req.body;
  if(estado){ await query('UPDATE pedidos SET estado=$1, updated_at=NOW() WHERE id=$2', [estado, req.params.id]); }
  if(usuario_id){ await query('UPDATE pedidos SET usuario_id=$1 WHERE id=$2', [usuario_id, req.params.id]); }
  if(items){
    await query('DELETE FROM pedido_items WHERE pedido_id=$1', [req.params.id]);
    for(const it of items){ await query(`INSERT INTO pedido_items (pedido_id, producto_id, nombre_producto, cantidad, precio_unitario, subtotal) VALUES ($1,$2,$3,$4,$5,$6)`, [req.params.id, it.producto_id||null, it.nombre_producto||'', it.cantidad||1, it.precio_unitario||0, (it.cantidad||1)*(it.precio_unitario||0)]); }
    if(total!==undefined){ await query('UPDATE pedidos SET total=$1 WHERE id=$2', [total, req.params.id]); }
  }
  res.json({ ok: true });
});
app.post('/api/pedidos/:id/archivar', auth, adminAuth, async (req,res)=>{ await query('UPDATE pedidos SET archivado=true WHERE id=$1', [req.params.id]); res.json({ ok: true }); });
app.delete('/api/pedidos/:id', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM pedidos WHERE id=$1', [req.params.id]); res.json({ ok: true }); });

// STATS
app.get('/api/stats', auth, adminAuth, async (req,res)=>{
  const { seccion_id, desde, hasta } = req.query;
  let where=''; let params=[]; let idx=1;
  if(seccion_id && seccion_id!=='all'){ where+=` WHERE seccion_id=$${idx}`; params.push(seccion_id); idx++; }
  const totalPedidos = await query(`SELECT COUNT(*) FROM pedidos ${where}`, params);
  const totalVentas = await query(`SELECT COALESCE(SUM(total),0) as sum FROM pedidos ${where}`, params);
  const totalProductos = await query('SELECT COUNT(*) FROM productos');
  const totalUsuarios = await query('SELECT COUNT(*) FROM usuarios');
  const ventasDia = await query(`SELECT DATE(created_at) as fecha, SUM(total) as total FROM pedidos ${where} GROUP BY DATE(created_at) ORDER BY fecha DESC LIMIT 14`, params);
  res.json({ total_pedidos: parseInt(totalPedidos.rows[0].count), total_ventas: parseFloat(totalVentas.rows[0].sum), total_productos: parseInt(totalProductos.rows[0].count), total_usuarios: parseInt(totalUsuarios.rows[0].count), ventas_por_dia: ventasDia.rows });
});

// ========== CUPONES / PROMOS / POPUPS / BADGES / ETC ==========
app.get('/api/cupones', auth, adminAuth, async (req,res)=>{ const { rows } = await query('SELECT * FROM cupones ORDER BY id DESC'); res.json(rows); });
app.post('/api/cupones/validar', auth, async (req,res)=>{
  const { codigo, subtotal } = req.body;
  const { rows } = await query('SELECT * FROM cupones WHERE codigo=$1 AND activo=true', [codigo]);
  const c = rows[0]; if(!c) return res.status(400).json({ error: 'Cupón inválido' });
  if(c.uso_maximo>0 && c.usos_actuales>=c.uso_maximo) return res.status(400).json({ error: 'Cupón agotado' });
  let descuento=0; if(c.tipo==='porcentaje') descuento = subtotal*c.valor/100; else if(c.tipo==='monto_fijo') descuento = c.valor;
  res.json({ descuento, cupon: c });
});
app.post('/api/cupones', auth, adminAuth, async (req,res)=>{ const f=req.body; const { rows } = await query('INSERT INTO cupones (codigo,tipo,valor,compra_minima,uso_maximo,secciones_ids,categoria,medio_pago,activo) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *', [f.codigo, f.tipo||'porcentaje', f.valor||0, f.monto_minimo||0, f.uso_maximo||0, f.secciones_ids||'', f.categoria||'', f.metodo_pago||'', true]); res.json(rows[0]); });
app.put('/api/cupones/:id', auth, adminAuth, async (req,res)=>{ const f=req.body; await query('UPDATE cupones SET codigo=$1, tipo=$2, valor=$3, compra_minima=$4, uso_maximo=$5, secciones_ids=$6, categoria=$7, medio_pago=$8 WHERE id=$9', [f.codigo,f.tipo,f.valor,f.monto_minimo,f.uso_maximo,f.secciones_ids,f.categoria,f.metodo_pago,req.params.id]); res.json({ ok: true }); });
app.delete('/api/cupones/:id', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM cupones WHERE id=$1', [req.params.id]); res.json({ ok: true }); });

app.get('/api/promociones', auth, adminAuth, async (req,res)=>{ const { rows } = await query('SELECT * FROM promociones ORDER BY id DESC'); res.json(rows); });
app.get('/api/promociones/activas', async (req,res)=>{ const { rows } = await query('SELECT * FROM promociones WHERE activa=true'); res.json(rows); });
app.post('/api/promociones', auth, adminAuth, async (req,res)=>{ const f=req.body; const { rows } = await query('INSERT INTO promociones (nombre,tipo,valor,secciones_ids,categoria,productos_ids,activa) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [f.nombre,f.tipo,f.valor,f.secciones_ids||'',f.categoria||'',f.productos_ids||'',true]); res.json(rows[0]); });
app.put('/api/promociones/:id', auth, adminAuth, async (req,res)=>{ const f=req.body; await query('UPDATE promociones SET nombre=$1, tipo=$2, valor=$3, secciones_ids=$4, categoria=$5, productos_ids=$6 WHERE id=$7', [f.nombre,f.tipo,f.valor,f.secciones_ids,f.categoria,f.productos_ids,req.params.id]); res.json({ ok: true }); });
app.delete('/api/promociones/:id', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM promociones WHERE id=$1', [req.params.id]); res.json({ ok: true }); });

app.get('/api/popups', async (req,res)=>{ const { rows } = await query('SELECT * FROM popups WHERE activo=true ORDER BY id DESC LIMIT 1'); res.json(rows); });
app.get('/api/popups/all', auth, adminAuth, async (req,res)=>{ const { rows } = await query('SELECT * FROM popups ORDER BY id DESC'); res.json(rows); });
app.post('/api/popups', auth, adminAuth, async (req,res)=>{ const f=req.body; const { rows } = await query('INSERT INTO popups (titulo,imagen,url_destino,secciones_ids,activo) VALUES ($1,$2,$3,$4,$5) RETURNING *', [f.titulo,f.imagen,f.url_destino,f.secciones_ids||'',f.activo!==false]); res.json(rows[0]); });
app.put('/api/popups/:id', auth, adminAuth, async (req,res)=>{ const f=req.body; await query('UPDATE popups SET titulo=$1, imagen=$2, url_destino=$3, secciones_ids=$4, activo=$5 WHERE id=$6', [f.titulo,f.imagen,f.url_destino,f.secciones_ids,f.activo,req.params.id]); res.json({ ok: true }); });
app.delete('/api/popups/:id', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM popups WHERE id=$1', [req.params.id]); res.json({ ok: true }); });

app.get('/api/badges', async (req,res)=>{
  const { seccion_id } = req.query; const { rows } = await query('SELECT * FROM badges WHERE visible=true ORDER BY orden');
  if(seccion_id){ const filtered = rows.filter(b=>!b.secciones_ids || b.secciones_ids.split(',').map(Number).includes(parseInt(seccion_id))); return res.json(filtered); }
  res.json(rows);
});
app.get('/api/badges/all', auth, adminAuth, async (req,res)=>{ const { rows } = await query('SELECT * FROM badges ORDER BY orden'); res.json(rows); });
app.post('/api/badges', auth, adminAuth, async (req,res)=>{ const f=req.body; const { rows } = await query('INSERT INTO badges (icono,texto,orden,visible,secciones_ids) VALUES ($1,$2,$3,$4,$5) RETURNING *', [f.icono||'⭐',f.texto,f.orden||0,f.visible!==false,f.secciones_ids||'']); res.json(rows[0]); });
app.put('/api/badges/:id', auth, adminAuth, async (req,res)=>{ const f=req.body; await query('UPDATE badges SET icono=$1, texto=$2, orden=$3, visible=$4, secciones_ids=$5 WHERE id=$6', [f.icono,f.texto,f.orden,f.visible,f.secciones_ids,req.params.id]); res.json({ ok: true }); });
app.delete('/api/badges/:id', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM badges WHERE id=$1', [req.params.id]); res.json({ ok: true }); });

app.get('/api/metodos-pago', async (req,res)=>{ const { seccion_id } = req.query; let sql='SELECT * FROM metodos_pago WHERE activo=true'; let params=[]; if(seccion_id){ sql+=' AND (seccion_id=$1 OR seccion_id IS NULL)'; params=[seccion_id]; } sql+=' ORDER BY orden'; const { rows } = await query(sql, params); res.json(rows); });
app.get('/api/metodos-pago/all', auth, adminAuth, async (req,res)=>{ const { rows } = await query('SELECT * FROM metodos_pago ORDER BY orden'); res.json(rows); });
app.post('/api/metodos-pago', auth, adminAuth, async (req,res)=>{ const f=req.body; const { rows } = await query('INSERT INTO metodos_pago (nombre,descripcion,instrucciones,icono,seccion_id,activo,orden) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [f.nombre,f.descripcion||'',f.instrucciones||'',f.icono||'💳',f.seccion_id||null,f.activo!==false,f.orden||0]); res.json(rows[0]); });
app.put('/api/metodos-pago/:id', auth, adminAuth, async (req,res)=>{ const f=req.body; await query('UPDATE metodos_pago SET nombre=$1, descripcion=$2, instrucciones=$3, icono=$4, seccion_id=$5, activo=$6, orden=$7 WHERE id=$8', [f.nombre,f.descripcion,f.instrucciones,f.icono,f.seccion_id,f.activo,f.orden,req.params.id]); res.json({ ok: true }); });
app.delete('/api/metodos-pago/:id', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM metodos_pago WHERE id=$1', [req.params.id]); res.json({ ok: true }); });

app.get('/api/menu', async (req,res)=>{ const { rows } = await query('SELECT * FROM menu_items WHERE visible=true ORDER BY orden'); res.json(rows); });
app.get('/api/menu/all', auth, adminAuth, async (req,res)=>{ const { rows } = await query('SELECT * FROM menu_items ORDER BY orden'); res.json(rows); });
app.post('/api/menu', auth, adminAuth, async (req,res)=>{ const f=req.body; const { rows } = await query('INSERT INTO menu_items (titulo,url,tipo,orden,visible) VALUES ($1,$2,$3,$4,$5) RETURNING *', [f.titulo,f.url||'',f.tipo||'link',f.orden||0,f.visible!==false]); res.json(rows[0]); });
app.put('/api/menu/:id', auth, adminAuth, async (req,res)=>{ const f=req.body; await query('UPDATE menu_items SET titulo=$1, url=$2, tipo=$3, orden=$4, visible=$5 WHERE id=$6', [f.titulo,f.url,f.tipo,f.orden,f.visible,req.params.id]); res.json({ ok: true }); });
app.delete('/api/menu/:id', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM menu_items WHERE id=$1', [req.params.id]); res.json({ ok: true }); });

app.get('/api/redes-sociales', async (req,res)=>{ const { rows } = await query('SELECT * FROM redes_sociales ORDER BY orden'); res.json(rows); });
app.put('/api/redes-sociales', auth, adminAuth, async (req,res)=>{ const { redes } = req.body; for(const r of redes){ await query('UPDATE redes_sociales SET url=$1, activo=$2 WHERE id=$3', [r.url, r.activo, r.id]); } res.json({ ok: true }); });

app.get('/api/design', async (req,res)=>{ const { rows } = await query('SELECT * FROM design_config'); const obj={}; rows.forEach(r=>obj[r.clave]=r.valor); res.json(obj); });
app.put('/api/design', auth, adminAuth, async (req,res)=>{ for(const [k,v] of Object.entries(req.body)){ await query('INSERT INTO design_config (clave, valor) VALUES ($1,$2) ON CONFLICT (clave) DO UPDATE SET valor=$2', [k, String(v)]); } res.json({ ok: true }); });

app.get('/api/paginas', async (req,res)=>{ const { rows } = await query('SELECT * FROM paginas_info WHERE visible=true ORDER BY orden'); res.json(rows); });
app.post('/api/paginas', auth, adminAuth, async (req,res)=>{ const f=req.body; const { rows } = await query('INSERT INTO paginas_info (titulo,slug,contenido,orden,visible) VALUES ($1,$2,$3,$4,$5) RETURNING *', [f.titulo,f.slug,f.contenido,f.orden||0,f.visible!==false]); res.json(rows[0]); });
app.put('/api/paginas/:id', auth, adminAuth, async (req,res)=>{ const f=req.body; await query('UPDATE paginas_info SET titulo=$1, slug=$2, contenido=$3, orden=$4, visible=$5 WHERE id=$6', [f.titulo,f.slug,f.contenido,f.orden,f.visible,req.params.id]); res.json({ ok: true }); });
app.delete('/api/paginas/:id', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM paginas_info WHERE id=$1', [req.params.id]); res.json({ ok: true }); });

app.get('/api/slider', async (req,res)=>{ const { rows } = await query('SELECT * FROM slider_banners WHERE activo=true ORDER BY orden'); res.json(rows); });
app.get('/api/slider/all', auth, adminAuth, async (req,res)=>{ const { rows } = await query('SELECT * FROM slider_banners ORDER BY orden'); res.json(rows); });
app.post('/api/slider', auth, adminAuth, async (req,res)=>{ const f=req.body; const { rows } = await query('INSERT INTO slider_banners (titulo,imagen,url_destino,orden,activo) VALUES ($1,$2,$3,$4,$5) RETURNING *', [f.titulo||'',f.imagen,f.url_destino||'',f.orden||0,f.activo!==false]); res.json(rows[0]); });
app.put('/api/slider/:id', auth, adminAuth, async (req,res)=>{ const f=req.body; await query('UPDATE slider_banners SET titulo=$1, imagen=$2, url_destino=$3, orden=$4, activo=$5 WHERE id=$6', [f.titulo,f.imagen,f.url_destino,f.orden,f.activo,req.params.id]); res.json({ ok: true }); });
app.delete('/api/slider/:id', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM slider_banners WHERE id=$1', [req.params.id]); res.json({ ok: true }); });

app.get('/api/favoritos', auth, async (req,res)=>{ const { rows } = await query('SELECT f.*, p.nombre, p.modelo, p.categoria, p.precio_base, p.imagen, p.stock, p.seccion_id FROM favoritos f JOIN productos p ON p.id=f.producto_id WHERE f.usuario_id=$1', [req.user.id]); res.json(rows); });
app.post('/api/favoritos/:id', auth, async (req,res)=>{ await query('INSERT INTO favoritos (usuario_id, producto_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, req.params.id]); res.json({ ok: true }); });
app.delete('/api/favoritos/:id', auth, async (req,res)=>{ await query('DELETE FROM favoritos WHERE usuario_id=$1 AND producto_id=$2', [req.user.id, req.params.id]); res.json({ ok: true }); });

app.post('/api/notificar-stock', async (req,res)=>{ const { producto_id, email } = req.body; await query('INSERT INTO notificaciones_stock (producto_id, email) VALUES ($1,$2)', [producto_id, email]); res.json({ ok: true }); });

app.get('/api/envio/custom', async (req,res)=>{ const { seccion_id } = req.query; let sql='SELECT * FROM envios_custom WHERE activo=true'; let params=[]; if(seccion_id){ sql+=' AND (seccion_id=$1 OR seccion_id IS NULL)'; params=[seccion_id]; } sql+=' ORDER BY orden'; const { rows } = await query(sql, params); res.json(rows); });
app.get('/api/envio/custom/all', auth, adminAuth, async (req,res)=>{ const { rows } = await query('SELECT * FROM envios_custom ORDER BY orden'); res.json(rows); });
app.post('/api/envio/custom', auth, adminAuth, async (req,res)=>{ const f=req.body; const { rows } = await query('INSERT INTO envios_custom (seccion_id,nombre,descripcion,precio,tipo,activo,gratis_desde,tiempo_estimado,icono,orden) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *', [f.seccion_id||null,f.nombre,f.descripcion||'',f.precio||0,f.tipo||'fijo',f.activo!==false,f.gratis_desde||0,f.tiempo_estimado||'',f.icono||'truck',f.orden||0]); res.json(rows[0]); });
app.put('/api/envio/custom/:id', auth, adminAuth, async (req,res)=>{ const f=req.body; await query('UPDATE envios_custom SET seccion_id=$1, nombre=$2, descripcion=$3, precio=$4, tipo=$5, activo=$6, gratis_desde=$7, tiempo_estimado=$8, icono=$9, orden=$10 WHERE id=$11', [f.seccion_id,f.nombre,f.descripcion,f.precio,f.tipo,f.activo,f.gratis_desde,f.tiempo_estimado,f.icono,f.orden,req.params.id]); res.json({ ok: true }); });
app.delete('/api/envio/custom/:id', auth, adminAuth, async (req,res)=>{ await query('DELETE FROM envios_custom WHERE id=$1', [req.params.id]); res.json({ ok: true }); });

app.get('/api/busqueda-global', async (req,res)=>{
  const { q } = req.query; if(!q || q.length<2) return res.json({ total:0, resultados:[] });
  const { rows: secs } = await query('SELECT * FROM secciones');
  const resultados=[];
  for(const sec of secs){
    const { rows } = await query(`SELECT * FROM productos WHERE seccion_id=$1 AND (nombre ILIKE $2 OR modelo ILIKE $2 OR categoria ILIKE $2) AND visible=true LIMIT 20`, [sec.id, `%${q}%`]);
    if(rows.length) resultados.push({ seccion: sec, productos: rows });
  }
  res.json({ total: resultados.reduce((s,r)=>s+r.productos.length,0), resultados });
});

app.get('/api/dolar-blue', async (req,res)=>{
  try{
    const r = await fetch('https://dolarapi.com/v1/dolares/blue');
    const data = await r.json();
    res.json({ venta: data.venta });
  }catch{
    const { rows } = await query(`SELECT valor FROM configuracion WHERE clave='dolar_blue'`);
    res.json({ venta: rows[0] ? parseFloat(rows[0].valor) : 1500 });
  }
});

// ANDREANI MOCK + REAL
app.post('/api/andreani/cotizar', async (req,res)=>{
  const { cp_destino, peso, volumen } = req.body;
  if(!cp_destino) return res.status(400).json({ error: 'CP requerido' });
  // Si hay credenciales, llamar API real (simplificado)
  if(process.env.ANDREANI_USER && process.env.ANDREANI_DEBUG!=='true'){
    // TODO: integración real
  }
  // Mock: costo base 3500 + 200 por kg + random por CP
  const costo = 3500 + (parseFloat(peso)||0.5)*800 + (parseInt(cp_destino)%100)*10;
  res.json({ costo: Math.round(costo), tiempo: '1 a 3 días hábiles' });
});
app.get('/api/andreani/sucursales', async (req,res)=>{
  const { cp } = req.query;
  res.json([{ direccion: { calle: 'Av. Principal', numero: '123', localidad: 'CP '+cp } }]);
});

// ROOT
app.get('/', (req,res)=>res.json({ name: 'Sistema Unificado API v5', version: '5.0.0', status: 'ok' }));

app.listen(PORT, ()=>console.log(`[API v5] Running on ${PORT}`));
