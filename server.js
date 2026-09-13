import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import { z } from 'zod';

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL é obrigatória. O sistema não usa banco de dados demo.');
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET deve ter pelo menos 32 caracteres.');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 10, ssl: isProd ? { rejectUnauthorized:false } : false });
const uploadsDir = path.join(__dirname, 'uploads');
await fs.mkdir(uploadsDir, {recursive:true});

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',').map(x=>x.trim()) || false, credentials:true }));
app.use(express.json({limit:'1mb'}));
app.use(cookieParser());
app.use('/api/', rateLimit({windowMs:15*60*1000, limit:300, standardHeaders:'draft-8', legacyHeaders:false}));
app.use(express.static(path.join(__dirname,'public')));
app.use('/uploads', express.static(uploadsDir, { maxAge:'7d', immutable:true }));

const upload = multer({
  storage: multer.diskStorage({
    destination: (_,__,cb)=>cb(null,uploadsDir),
    filename: (_,file,cb)=>{
      const ext=path.extname(file.originalname).toLowerCase();
      cb(null, `${crypto.randomUUID()}${ext}`);
    }
  }),
  limits:{fileSize:Number(process.env.MAX_UPLOAD_MB||5)*1024*1024, files:5},
  fileFilter: (_,file,cb)=>cb(null,/^image\/(jpeg|png|webp|gif)$/i.test(file.mimetype))
});

const slugify = s => String(s).normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,180);
const money = n => Number(n||0);
const sign = payload => jwt.sign(payload,process.env.JWT_SECRET,{expiresIn:'8h'});
const cookieOpts = {httpOnly:true,sameSite:'lax',secure:process.env.COOKIE_SECURE==='true',maxAge:8*60*60*1000,path:'/'};

async function q(text, params=[]){return pool.query(text,params);}
async function audit(req, user, action, entityType, entityId=null, metadata={}) {
  await q(`INSERT INTO audit_logs(store_id,user_id,action,entity_type,entity_id,ip,user_agent,metadata)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
    [user?.store_id||null,user?.id||null,action,entityType,entityId,req.ip,req.get('user-agent')||'',metadata]);
}
function publicStore(s){ return {id:s.id,name:s.name,slug:s.slug,description:s.description,region:s.region,city:s.city,neighborhood:s.neighborhood,phone:s.phone,email:s.email,logoUrl:s.logo_url,coverUrl:s.cover_url,hours:s.hours,socialLinks:s.social_links,verified:s.verified,status:s.status}; }
function publicProduct(p){ return {id:p.id,name:p.name,slug:p.slug,description:p.description,category:p.category_name,categoryId:p.category_id,price:money(p.price_fcfa),promoPrice:p.promo_price_fcfa==null?null:money(p.promo_price_fcfa),published:p.published,status:p.status,images:p.images||[],variants:p.variants||[]}; }

async function auth(req,res,next){
  try{
    const token=req.cookies.bm_access;
    if(!token) return res.status(401).json({error:'Autenticação necessária.'});
    const data=jwt.verify(token,process.env.JWT_SECRET);
    const r=await q(`SELECT id,store_id,name,email,role,active FROM users WHERE id=$1`,[data.sub]);
    if(!r.rows[0]||!r.rows[0].active) return res.status(401).json({error:'Sessão inválida.'});
    req.user=r.rows[0]; next();
  }catch{res.status(401).json({error:'Sessão inválida ou expirada.'});}
}
const role = (...roles)=>(req,res,next)=>roles.includes(req.user.role)?next():res.status(403).json({error:'Permissão insuficiente.'});
const validate = (schema, source='body') => (req,res,next)=>{const r=schema.safeParse(req[source]); if(!r.success)return res.status(400).json({error:'Dados inválidos.',details:r.error.flatten()}); req[source]=r.data; next();};

app.get('/api/health', async (_,res)=>{try{await q('SELECT 1');res.json({ok:true,service:'bm-business',database:'connected',version:'2.0.0'});}catch{res.status(503).json({ok:false,database:'unavailable'});}});
app.post('/api/auth/register',rateLimit({windowMs:60*60*1000,limit:10}),validate(z.object({
  storeName:z.string().trim().min(2).max(160), ownerName:z.string().trim().min(2).max(160),
  email:z.string().trim().email().max(255), password:z.string().min(10).max(128),
  phone:z.string().trim().max(40).optional().default('')
})),async(req,res)=>{
  const {storeName,ownerName,email,password,phone}=req.body;
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const exists=await client.query('SELECT id FROM users WHERE email=$1',[email.toLowerCase()]);
    if(exists.rows[0]){await client.query('ROLLBACK');return res.status(409).json({error:'Este email já está registado.'});}
    const base=slugify(storeName)||crypto.randomUUID();
    let slug=base, i=1;
    while((await client.query('SELECT 1 FROM stores WHERE slug=$1',[slug])).rows[0]) slug=`${base}-${i++}`;
    const store=(await client.query(`INSERT INTO stores(name,slug,owner_name,phone,email) VALUES($1,$2,$3,$4,$5) RETURNING *`,[storeName,slug,ownerName,phone,email.toLowerCase()])).rows[0];
    const hash=await bcrypt.hash(password,12);
    const user=(await client.query(`INSERT INTO users(store_id,name,email,password_hash,role) VALUES($1,$2,$3,$4,'owner') RETURNING id,store_id,name,email,role`,[store.id,ownerName,email.toLowerCase(),hash])).rows[0];
    await client.query('COMMIT');
    res.cookie('bm_access',sign({sub:user.id,store_id:user.store_id,role:user.role}),cookieOpts);
    await audit(req,user,'REGISTER','store',store.id);
    res.status(201).json({user,store:publicStore(store)});
  }catch(e){await client.query('ROLLBACK');res.status(500).json({error:'Não foi possível criar a conta.'});}finally{client.release();}
});
app.post('/api/auth/login',rateLimit({windowMs:15*60*1000,limit:10}),validate(z.object({email:z.string().email(),password:z.string().min(1)})),async(req,res)=>{
  const r=await q(`SELECT u.id,u.store_id,u.name,u.email,u.password_hash,u.role,u.active,s.status store_status
                   FROM users u JOIN stores s ON s.id=u.store_id WHERE u.email=$1`,[req.body.email.toLowerCase()]);
  const u=r.rows[0];
  if(!u||!u.active||u.store_status!=='active'||!(await bcrypt.compare(req.body.password,u.password_hash))) return res.status(401).json({error:'Email ou palavra-passe incorretos.'});
  res.cookie('bm_access',sign({sub:u.id,store_id:u.store_id,role:u.role}),cookieOpts);
  const user={id:u.id,store_id:u.store_id,name:u.name,email:u.email,role:u.role};
  await audit(req,user,'LOGIN','user',u.id);
  res.json({user});
});
app.post('/api/auth/logout',auth,async(req,res)=>{await audit(req,req.user,'LOGOUT','user',req.user.id);res.clearCookie('bm_access',{httpOnly:true,sameSite:'lax',secure:process.env.COOKIE_SECURE==='true',path:'/'});res.json({ok:true});});
app.get('/api/auth/me',auth,async(req,res)=>res.json({user:req.user}));

app.get('/api/categories',auth,async(_,res)=>res.json((await q(`SELECT id,name,slug,parent_id FROM categories WHERE active=true ORDER BY name`)).rows));
app.get('/api/store',auth,async(req,res)=>res.json(publicStore((await q('SELECT * FROM stores WHERE id=$1',[req.user.store_id])).rows[0])));
app.patch('/api/store',auth,role('owner','admin'),validate(z.object({
  name:z.string().trim().min(2).max(160),description:z.string().max(5000),region:z.string().max(120),city:z.string().max(120),neighborhood:z.string().max(160),
  phone:z.string().max(40),email:z.string().email(),hours:z.record(z.string(),z.string()).optional(),socialLinks:z.record(z.string(),z.string()).optional()
})),async(req,res)=>{
  const d=req.body,s=(await q(`UPDATE stores SET name=$1,description=$2,region=$3,city=$4,neighborhood=$5,phone=$6,email=$7,hours=COALESCE($8,hours),social_links=COALESCE($9,social_links),updated_at=now() WHERE id=$10 RETURNING *`,
  [d.name,d.description,d.region,d.city,d.neighborhood,d.phone,d.email,d.hours?JSON.stringify(d.hours):null,d.socialLinks?JSON.stringify(d.socialLinks):null,req.user.store_id])).rows[0];
  await audit(req,req.user,'UPDATE','store',s.id);res.json(publicStore(s));
});
app.post('/api/store/images',auth,role('owner','admin'),upload.fields([{name:'logo',maxCount:1},{name:'cover',maxCount:1}]),async(req,res)=>{
  const logo=req.files?.logo?.[0],cover=req.files?.cover?.[0];
  const vals=[logo?`/uploads/${logo.filename}`:null,cover?`/uploads/${cover.filename}`:null,req.user.store_id];
  const s=(await q(`UPDATE stores SET logo_url=COALESCE($1,logo_url),cover_url=COALESCE($2,cover_url),updated_at=now() WHERE id=$3 RETURNING *`,vals)).rows[0];
  res.json(publicStore(s));
});

const productSchema=z.object({
  name:z.string().trim().min(2).max(220),description:z.string().max(10000).optional().default(''),
  categoryId:z.string().uuid(),priceFcfa:z.coerce.number().int().min(0),promoPriceFcfa:z.coerce.number().int().min(0).nullable().optional(),
  variants:z.array(z.object({sku:z.string().trim().min(1).max(120),name:z.string().max(160).default(''),color:z.string().max(80).default(''),size:z.string().max(80).default(''),stock:z.coerce.number().int().min(0)})).max(100).default([])
});
async function productById(id,storeId){
 const p=(await q(`SELECT p.*,c.name category_name,
   COALESCE((SELECT json_agg(json_build_object('id',i.id,'url',i.url,'altText',i.alt_text) ORDER BY i.sort_order) FROM product_images i WHERE i.product_id=p.id),'[]') images,
   COALESCE((SELECT json_agg(json_build_object('id',v.id,'sku',v.sku,'name',v.name,'color',v.color,'size',v.size,'stock',v.stock,'active',v.active) ORDER BY v.sku) FROM product_variants v WHERE v.product_id=p.id),'[]') variants
   FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE p.id=$1 AND p.store_id=$2`,[id,storeId])).rows[0];
 return p;
}
app.get('/api/products',auth,async(req,res)=>{
 const term=String(req.query.q||'').trim(), statusFilter=req.query.status;
 const params=[req.user.store_id]; let where='p.store_id=$1';
 if(term){params.push(`%${term}%`);where+=' AND (p.name ILIKE $'+params.length+' OR p.description ILIKE $'+params.length+')';}
 if(['draft','active','out_of_stock','archived'].includes(statusFilter)){params.push(statusFilter);where+=' AND p.status=$'+params.length;}
 const rows=(await q(`SELECT p.*,c.name category_name,
 COALESCE((SELECT json_agg(json_build_object('id',i.id,'url',i.url,'altText',i.alt_text) ORDER BY i.sort_order) FROM product_images i WHERE i.product_id=p.id),'[]') images,
 COALESCE((SELECT json_agg(json_build_object('id',v.id,'sku',v.sku,'name',v.name,'color',v.color,'size',v.size,'stock',v.stock,'active',v.active) ORDER BY v.sku) FROM product_variants v WHERE v.product_id=p.id),'[]') variants
 FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE ${where} ORDER BY p.updated_at DESC`,params)).rows;
 res.json(rows.map(publicProduct));
});
app.post('/api/products',auth,role('owner','admin','staff'),validate(productSchema),async(req,res)=>{
 const d=req.body, slugBase=slugify(d.name)||crypto.randomUUID(); let slug=slugBase,i=1;
 while((await q('SELECT 1 FROM products WHERE store_id=$1 AND slug=$2',[req.user.store_id,slug])).rows[0])slug=`${slugBase}-${i++}`;
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const p=(await client.query(`INSERT INTO products(store_id,name,slug,description,category_id,price_fcfa,promo_price_fcfa,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
  [req.user.store_id,d.name,slug,d.description,d.categoryId,d.priceFcfa,d.promoPriceFcfa??null,d.variants.reduce((a,v)=>a+v.stock,0)>0?'active':'out_of_stock'])).rows[0];
  for(const v of d.variants) await client.query(`INSERT INTO product_variants(product_id,sku,name,color,size,stock) VALUES($1,$2,$3,$4,$5,$6)`,[p.id,v.sku,v.name,v.color,v.size,v.stock]);
  await client.query('COMMIT'); const full=await productById(p.id,req.user.store_id); await audit(req,req.user,'CREATE','product',p.id);res.status(201).json(publicProduct(full));
 }catch(e){await client.query('ROLLBACK');res.status(400).json({error:e.code==='23505'?'SKU ou produto já existe.':'Não foi possível criar o produto.'});}finally{client.release();}
});
app.patch('/api/products/:id',auth,role('owner','admin','staff'),validate(productSchema),async(req,res)=>{
 const id=req.params.id,d=req.body;
 const exists=await q('SELECT id FROM products WHERE id=$1 AND store_id=$2',[id,req.user.store_id]);if(!exists.rows[0])return res.status(404).json({error:'Produto não encontrado.'});
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  await client.query(`UPDATE products SET name=$1,description=$2,category_id=$3,price_fcfa=$4,promo_price_fcfa=$5,status=$6,updated_at=now() WHERE id=$7 AND store_id=$8`,
   [d.name,d.description,d.categoryId,d.priceFcfa,d.promoPriceFcfa??null,d.variants.reduce((a,v)=>a+v.stock,0)>0?'active':'out_of_stock',id,req.user.store_id]);
  await client.query('DELETE FROM product_variants WHERE product_id=$1',[id]);
  for(const v of d.variants)await client.query(`INSERT INTO product_variants(product_id,sku,name,color,size,stock) VALUES($1,$2,$3,$4,$5,$6)`,[id,v.sku,v.name,v.color,v.size,v.stock]);
  await client.query('COMMIT');const full=await productById(id,req.user.store_id);await audit(req,req.user,'UPDATE','product',id);res.json(publicProduct(full));
 }catch(e){await client.query('ROLLBACK');res.status(400).json({error:'Não foi possível atualizar o produto.'});}finally{client.release();}
});
app.delete('/api/products/:id',auth,role('owner','admin'),async(req,res)=>{
 const r=await q(`UPDATE products SET status='archived',published=false,updated_at=now() WHERE id=$1 AND store_id=$2 RETURNING id`,[req.params.id,req.user.store_id]);
 if(!r.rows[0])return res.status(404).json({error:'Produto não encontrado.'});await audit(req,req.user,'ARCHIVE','product',r.rows[0].id);res.json({ok:true});
});
app.post('/api/products/:id/images',auth,role('owner','admin','staff'),upload.array('images',5),async(req,res)=>{
 const p=await productById(req.params.id,req.user.store_id);if(!p)return res.status(404).json({error:'Produto não encontrado.'});
 const existing=await q('SELECT count(*)::int n FROM product_images WHERE product_id=$1',[p.id]);if(existing.rows[0].n+req.files.length>5)return res.status(400).json({error:'Cada produto pode ter no máximo 5 imagens.'});
 for(let i=0;i<req.files.length;i++)await q('INSERT INTO product_images(product_id,url,alt_text,sort_order) VALUES($1,$2,$3,$4)',[p.id,`/uploads/${req.files[i].filename}`,p.name,existing.rows[0].n+i]);
 const full=await productById(p.id,req.user.store_id);res.status(201).json(publicProduct(full));
});

app.post('/api/products/:id/publish',auth,role('owner','admin'),async(req,res)=>{
 const p=await productById(req.params.id,req.user.store_id);
 if(!p)return res.status(404).json({error:'Produto não encontrado.'});
 const stock=(p.variants||[]).reduce((a,v)=>a+Number(v.stock),0);
 if(!p.name||!p.category_name||stock<=0||(p.images||[]).length===0)return res.status(409).json({error:'Para publicar, o produto precisa de categoria, pelo menos uma imagem e estoque disponível.'});
 const pub=publicProduct(p);
 if(!process.env.BISSAU_MARKET_API_URL||!process.env.BISSAU_MARKET_API_KEY)return res.status(503).json({error:'A integração Bissau Market não está configurada. Defina BISSAU_MARKET_API_URL e BISSAU_MARKET_API_KEY.'});
 let response;
 try{response=await fetch(`${process.env.BISSAU_MARKET_API_URL.replace(/\/$/,'')}/api/business/products/publish`,{method:'POST',headers:{'content-type':'application/json','authorization':`Bearer ${process.env.BISSAU_MARKET_API_KEY}`},body:JSON.stringify({storeId:req.user.store_id,product:pub})});}
 catch{return res.status(502).json({error:'Não foi possível contactar o Bissau Market.'});}
 if(!response.ok)return res.status(502).json({error:`Bissau Market rejeitou a publicação (${response.status}).`});
 await q(`UPDATE products SET published=true,status='active',updated_at=now() WHERE id=$1 AND store_id=$2`,[p.id,req.user.store_id]);
 await audit(req,req.user,'PUBLISH','product',p.id,{destination:'bissau-market'});
 res.json({ok:true,product:pub});
});

app.get('/api/inventory',auth,async(req,res)=>{
 const rows=(await q(`SELECT p.id,p.name,p.status,COALESCE(sum(v.stock),0)::int stock,count(v.id)::int variants
 FROM products p LEFT JOIN product_variants v ON v.product_id=p.id AND v.active=true WHERE p.store_id=$1 GROUP BY p.id ORDER BY stock ASC,p.name`,[req.user.store_id])).rows;res.json(rows);
});
app.patch('/api/inventory/:variantId',auth,role('owner','admin','staff'),validate(z.object({stock:z.coerce.number().int().min(0)})),async(req,res)=>{
 const r=await q(`UPDATE product_variants v SET stock=$1 WHERE v.id=$2 AND EXISTS(SELECT 1 FROM products p WHERE p.id=v.product_id AND p.store_id=$3) RETURNING v.*`,[req.body.stock,req.params.variantId,req.user.store_id]);
 if(!r.rows[0])return res.status(404).json({error:'Variação não encontrada.'});await q(`UPDATE products p SET status=CASE WHEN COALESCE((SELECT sum(stock) FROM product_variants WHERE product_id=p.id),0)>0 THEN 'active' ELSE 'out_of_stock' END,updated_at=now() WHERE p.id=$1`,[r.rows[0].product_id]);res.json(r.rows[0]);
});

app.get('/api/dashboard',auth,async(req,res)=>{
 const sid=req.user.store_id;
 const [m,sales,top]=await Promise.all([
  q(`SELECT (SELECT COALESCE(sum(total_fcfa),0) FROM sales WHERE store_id=$1 AND status<>'cancelled') revenue,
      (SELECT count(*) FROM sales WHERE store_id=$1) sales,
      (SELECT count(*) FROM products WHERE store_id=$1 AND status<>'archived') products,
      (SELECT count(*) FROM products WHERE store_id=$1 AND published=true) published,
      (SELECT count(*) FROM customers WHERE store_id=$1) customers,
      (SELECT count(*) FROM messages m JOIN conversations c ON c.id=m.conversation_id WHERE c.store_id=$1 AND m.read_at IS NULL) messages,
      (SELECT count(*) FROM product_variants v JOIN products p ON p.id=v.product_id WHERE p.store_id=$1 AND v.stock BETWEEN 1 AND 5) low_stock`,[sid]),
  q(`SELECT s.id,s.total_fcfa,s.status,s.created_at,c.name customer FROM sales s LEFT JOIN customers c ON c.id=s.customer_id WHERE s.store_id=$1 ORDER BY s.created_at DESC LIMIT 8`,[sid]),
  q(`SELECT p.id,p.name,p.views,c.name category_name FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE p.store_id=$1 AND p.status<>'archived' ORDER BY p.views DESC LIMIT 5`,[sid])
 ]);
 res.json({metrics:m.rows[0],recentSales:sales.rows,topProducts:top.rows,store:publicStore((await q('SELECT * FROM stores WHERE id=$1',[sid])).rows[0])});
});

app.get('/api/sales',auth,async(req,res)=>res.json((await q(`SELECT s.id,s.total_fcfa,s.status,s.created_at,c.name customer FROM sales s LEFT JOIN customers c ON c.id=s.customer_id WHERE s.store_id=$1 ORDER BY s.created_at DESC`,[req.user.store_id])).rows));
app.post('/api/sales',auth,role('owner','admin','staff'),validate(z.object({customerName:z.string().trim().min(1).max(160),customerPhone:z.string().trim().max(40).optional().default(''),totalFcfa:z.coerce.number().int().positive(),status:z.enum(['pending','processing','completed']).default('completed')})),async(req,res)=>{
 const d=req.body,client=await pool.connect();
 try{
  await client.query('BEGIN');
  let c=(await client.query('SELECT * FROM customers WHERE store_id=$1 AND phone=$2',[req.user.store_id,d.customerPhone])).rows[0];
  if(!c)c=(await client.query(`INSERT INTO customers(store_id,name,phone) VALUES($1,$2,$3) RETURNING *`,[req.user.store_id,d.customerName,d.customerPhone])).rows[0];
  else await client.query('UPDATE customers SET name=$1,updated_at=now() WHERE id=$2',[d.customerName,c.id]);
  const sale=(await client.query(`INSERT INTO sales(store_id,customer_id,total_fcfa,status) VALUES($1,$2,$3,$4) RETURNING *`,[req.user.store_id,c.id,d.totalFcfa,d.status])).rows[0];
  await client.query('COMMIT');await audit(req,req.user,'CREATE','sale',sale.id);res.status(201).json(sale);
 }catch{await client.query('ROLLBACK');res.status(400).json({error:'Não foi possível registar a venda.'});}finally{client.release();}
});
app.get('/api/customers',auth,async(req,res)=>res.json((await q(`SELECT c.*,count(s.id)::int purchases,COALESCE(sum(s.total_fcfa),0)::int total,max(s.created_at) last_purchase FROM customers c LEFT JOIN sales s ON s.customer_id=c.id WHERE c.store_id=$1 GROUP BY c.id ORDER BY c.updated_at DESC`,[req.user.store_id])).rows));

app.get('/api/conversations',auth,async(req,res)=>res.json((await q(`SELECT c.id,c.status,c.updated_at,cu.name customer,p.name product,
 (SELECT body FROM messages WHERE conversation_id=c.id ORDER BY created_at DESC LIMIT 1) preview,
 (SELECT count(*) FROM messages WHERE conversation_id=c.id AND read_at IS NULL AND sender_user_id IS NULL)::int unread
 FROM conversations c LEFT JOIN customers cu ON cu.id=c.customer_id LEFT JOIN products p ON p.id=c.product_id WHERE c.store_id=$1 ORDER BY c.updated_at DESC`,[req.user.store_id])).rows));
app.get('/api/conversations/:id/messages',auth,async(req,res)=>{
 const ok=(await q('SELECT id FROM conversations WHERE id=$1 AND store_id=$2',[req.params.id,req.user.store_id])).rows[0];if(!ok)return res.status(404).json({error:'Conversa não encontrada.'});
 res.json((await q(`SELECT id,body,sender_user_id,read_at,created_at FROM messages WHERE conversation_id=$1 ORDER BY created_at`,[req.params.id])).rows);
});
app.post('/api/conversations/:id/messages',auth,role('owner','admin','staff'),validate(z.object({body:z.string().trim().min(1).max(5000)})),async(req,res)=>{
 const ok=(await q('SELECT id FROM conversations WHERE id=$1 AND store_id=$2',[req.params.id,req.user.store_id])).rows[0];if(!ok)return res.status(404).json({error:'Conversa não encontrada.'});
 const m=(await q('INSERT INTO messages(conversation_id,sender_user_id,body) VALUES($1,$2,$3) RETURNING *',[req.params.id,req.user.id,req.body.body])).rows[0];
 await q('UPDATE conversations SET updated_at=now() WHERE id=$1',[req.params.id]);res.status(201).json(m);
});

app.get('/api/notifications',auth,async(req,res)=>res.json((await q(`SELECT id,type,title,body,read_at,created_at FROM notifications WHERE store_id=$1 AND (user_id=$2 OR user_id IS NULL) ORDER BY created_at DESC LIMIT 50`,[req.user.store_id,req.user.id])).rows));
app.post('/api/notifications/:id/read',auth,async(req,res)=>{await q('UPDATE notifications SET read_at=now() WHERE id=$1 AND store_id=$2 AND (user_id=$3 OR user_id IS NULL)',[req.params.id,req.user.store_id,req.user.id]);res.json({ok:true});});
app.get('/api/events',auth,(req,res)=>{res.setHeader('Content-Type','text/event-stream');res.setHeader('Cache-Control','no-cache');res.setHeader('Connection','keep-alive');res.flushHeaders?.();const ping=setInterval(()=>res.write(`event: ping\ndata: ${Date.now()}\\n\\n`),25000);req.on('close',()=>clearInterval(ping));});

app.get('/api/audit-logs',auth,role('owner','admin'),async(req,res)=>res.json((await q(`SELECT id,action,entity_type,entity_id,ip,metadata,created_at FROM audit_logs WHERE store_id=$1 ORDER BY created_at DESC LIMIT 200`,[req.user.store_id])).rows));

app.get('/api/public/stores/:slug',async(req,res)=>{
 const s=(await q(`SELECT * FROM stores WHERE slug=$1 AND status='active'`,[req.params.slug])).rows[0];if(!s)return res.status(404).json({error:'Loja não encontrada.'});
 const products=(await q(`SELECT p.*,c.name category_name,COALESCE((SELECT json_agg(json_build_object('url',i.url,'altText',i.alt_text) ORDER BY i.sort_order) FROM product_images i WHERE i.product_id=p.id),'[]') images,
 COALESCE((SELECT json_agg(json_build_object('sku',v.sku,'name',v.name,'color',v.color,'size',v.size,'stock',v.stock)) FROM product_variants v WHERE v.product_id=p.id AND v.active=true),'[]') variants
 FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE p.store_id=$1 AND p.published=true AND p.status='active' ORDER BY p.updated_at DESC`,[s.id])).rows;
 res.json({store:publicStore(s),products:products.map(publicProduct)});
});

app.use('/api',(_,res)=>res.status(404).json({error:'Endpoint não encontrado.'}));
app.use((err,req,res,next)=>{console.error(err);if(err instanceof multer.MulterError)return res.status(400).json({error:'Falha no upload: '+err.message});res.status(500).json({error:'Erro interno do servidor.'});});
app.get(/.*/,(_,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`BM Business production running on http://localhost:${PORT}`));
