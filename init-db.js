const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV==='production'?{rejectUnauthorized:false}:false });
async function init(){
  try{
    let schema = '';
    try{
      const v4Path = path.join(__dirname,'schema-v4.sql');
      if(fs.existsSync(v4Path)) schema = fs.readFileSync(v4Path,'utf8');
      else {
        const v2Path = path.join(__dirname,'schema-v2.sql');
        if(fs.existsSync(v2Path)) schema = fs.readFileSync(v2Path,'utf8');
      }
    }catch(e){ console.log('No schema file'); }
    if(schema) {
      await pool.query(schema).catch(e=>console.log('schema warn',e.message.slice(0,200)));
      console.log('[DB] Schema applied');
    }
    const {rows}=await pool.query('SELECT COUNT(*) FROM listas_precio').catch(()=>({rows:[{count:'1'}]}));
    if(parseInt(rows[0].count)===0){
      const listas=[['may_aaa','Mayorista AAA',1.00,0,'#2563eb'],['may_aa','Mayorista AA',1.15,15,'#7c3aed'],['may_a','Mayorista A',1.35,35,'#059669'],['minorista','Minorista',1.70,70,'#d97706'],['dropshipping','Dropshipping',2.20,120,'#dc2626']];
      for(const [id,nombre,mult,pct,color] of listas){ await pool.query('INSERT INTO listas_precio (id,nombre,multiplicador,color) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING',[id,nombre,mult,color]); }
    }
    const hash=await bcrypt.hash('admin',10);
    await pool.query(`INSERT INTO usuarios (nombre,usuario,password,rol,aprobado,activo,lista_precio_id) VALUES ('Admin','admin',$1,'admin',true,true,'may_aaa') ON CONFLICT DO NOTHING`,[hash]).catch(()=>{});
    await pool.query(`INSERT INTO secciones (nombre,slug,descripcion,ignorar_stock,permitir_sin_stock,cp_origen) VALUES
      ('Local','local','Venta presencial',false,false,'1888'),
      ('Deposito','deposito','Stock con control',false,false,'1888'),
      ('Mayorista','mayorista','Venta por mayor sin stock',true,true,'1888'),
      ('Digital','digital','Productos digitales',true,true,'1888')
      ON CONFLICT (slug) DO UPDATE SET ignorar_stock=EXCLUDED.ignorar_stock, permitir_sin_stock=EXCLUDED.permitir_sin_stock, cp_origen=EXCLUDED.cp_origen`).catch(e=>console.log('secciones warn',e.message));
    await pool.end(); console.log('[DB] Init V4 complete');
  }catch(e){ console.error('[DB] Init error',e); process.exit(1); }
}
init();
