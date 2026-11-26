import express from 'express';
import pg from 'pg';
import {randomBytes, scryptSync, timingSafeEqual, createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import rateLimit from 'express-rate-limit';
const app=express(), db=new pg.Pool({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:10000,idleTimeoutMillis:15000});
// Neon may close idle connections. Handle pool errors without terminating the server.
db.on('error',err=>console.warn('Idle PostgreSQL connection closed:',err.code||err.name));
const html=readFileSync(new URL('./index.html',import.meta.url),'utf8');
const bank=JSON.parse(html.match(/const QUIZZES = (\[[\s\S]*?\]);\n\n\/\* =+/)[1]);
const quizMap=new Map(bank.map(q=>[q.id,q]));
const hash=s=>createHash('sha256').update(s).digest('hex');
const token=()=>randomBytes(32).toString('hex');
function passwordHash(p){const salt=token();return salt+':'+scryptSync(p,salt,64).toString('hex')}
function checkPassword(p,stored){const [salt,key]=stored.split(':');const b=Buffer.from(key,'hex');return b.length===64&&timingSafeEqual(b,scryptSync(p,salt,64))}
const emailValid=e=>typeof e==='string'&&e.length<=254&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const passwordValid=p=>typeof p==='string'&&p.length>=12&&p.length<=128;
const emailNorm=e=>String(e||'').trim().toLowerCase();
const query=(sql,params=[])=>db.query(sql,params);
await query("CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'student' CHECK(role IN ('student','admin')),active BOOLEAN NOT NULL DEFAULT TRUE,created_at TIMESTAMPTZ DEFAULT now()); CREATE TABLE IF NOT EXISTS devices(id BIGSERIAL PRIMARY KEY,user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,device_hash TEXT NOT NULL,label TEXT NOT NULL,first_seen TIMESTAMPTZ DEFAULT now(),last_seen TIMESTAMPTZ DEFAULT now(),UNIQUE(user_id,device_hash)); CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,device_id BIGINT REFERENCES devices(id) ON DELETE CASCADE,expires TIMESTAMPTZ NOT NULL); CREATE TABLE IF NOT EXISTS attempts(id BIGSERIAL PRIMARY KEY,user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,quiz_id TEXT NOT NULL,started_at TIMESTAMPTZ DEFAULT now(),finished_at TIMESTAMPTZ,score INTEGER,total INTEGER,answers JSONB); CREATE TABLE IF NOT EXISTS activity(id BIGSERIAL PRIMARY KEY,user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,kind TEXT NOT NULL,detail TEXT,created_at TIMESTAMPTZ DEFAULT now()); CREATE INDEX IF NOT EXISTS idx_attempt_user ON attempts(user_id); CREATE INDEX IF NOT EXISTS idx_activity_user ON activity(user_id,created_at DESC)");
const adminEmail=emailNorm(process.env.ADMIN_EMAIL), adminPassword=process.env.ADMIN_PASSWORD;
if(!(await query("SELECT 1 FROM users WHERE role='admin' LIMIT 1")).rowCount){
 if(!emailValid(adminEmail)||!passwordValid(adminPassword))throw Error('Set ADMIN_EMAIL and ADMIN_PASSWORD (12+ characters) before first deployment');
 await query("INSERT INTO users(email,name,password_hash,role) VALUES($1,$2,$3,'admin') ON CONFLICT DO NOTHING",[adminEmail,'Administrator',passwordHash(adminPassword)]);
}

// Existing initial administrator becomes the owner; other accounts and results remain intact.
await query("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_owner BOOLEAN NOT NULL DEFAULT FALSE; ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '[]'::jsonb; CREATE UNIQUE INDEX IF NOT EXISTS one_platform_owner ON users(is_owner) WHERE is_owner");
await query("UPDATE users SET is_owner=TRUE WHERE id=(SELECT id FROM users WHERE role='admin' AND active ORDER BY created_at,id LIMIT 1) AND NOT EXISTS (SELECT 1 FROM users WHERE is_owner)");
await query("ALTER TABLE users ADD COLUMN IF NOT EXISTS pending BOOLEAN NOT NULL DEFAULT FALSE; ALTER TABLE users ADD COLUMN IF NOT EXISTS device_limit INTEGER NOT NULL DEFAULT 2 CHECK(device_limit BETWEEN 1 AND 20)");
const PERMISSIONS=['user_create','user_edit','user_block','user_password','user_delete','view_devices','view_results','view_activity','manage_sessions','full_admin'];
const fullAdmin=u=>u.role==='admin'&&(u.is_owner===true||u.permissions.includes('full_admin'));
const allowed=(u,key)=>u.role==='admin'&&(fullAdmin(u)||u.permissions.includes(key));
const manageable=(actor,target)=>!target.is_owner&&(actor.is_owner||target.role==='student'||(fullAdmin(actor)&&!fullAdmin(target)));
const validPermissions=p=>Array.isArray(p)&&p.every(x=>PERMISSIONS.includes(x))&&new Set(p).size===p.length;
const deny=res=>res.status(403).json({error:'Bu amal uchun ruxsat yo‘q'});

app.disable('x-powered-by');
app.set('trust proxy',1);
app.use(express.json({limit:'64kb'}));
app.use((req,res,next)=>{res.set({'X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','X-Frame-Options':'DENY','Cache-Control':'no-store'});if(!['GET','HEAD','OPTIONS'].includes(req.method)&&req.path!=='/telegram/webhook'&&req.get('X-ATT-Request')!=='1')return res.status(403).json({error:'So‘rov rad etildi'});next()});
const cookie=(req,name)=>{const match=(req.headers.cookie||'').split(';').map(v=>v.trim()).find(v=>v.startsWith(name+'='));return match?match.slice(name.length+1):''};
const cookieSettings={httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',path:'/'};
const wrap=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);
const activity=(uid,kind,detail='')=>query('INSERT INTO activity(user_id,kind,detail) VALUES($1,$2,$3)',[uid,kind,detail]);
const auth=wrap(async(req,res,next)=>{const t=cookie(req,'att_session');if(!t)return req.path==='/admin'?res.redirect('/'):res.status(401).json({error:'Hisobga kiring'});const result=await query('SELECT u.id,u.email,u.name,u.role,u.is_owner,u.permissions,s.device_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires>now() AND u.active',[hash(t)]);if(!result.rowCount)return req.path==='/admin'?res.redirect('/'):res.status(401).json({error:'Sessiya tugagan'});req.user=result.rows[0];await query('UPDATE devices SET last_seen=now() WHERE id=$1 AND last_seen < now()-interval \'30 seconds\'',[req.user.device_id]);next()});
const admin=(req,res,next)=>req.user.role==='admin'?next():res.status(403).json({error:'Ruxsat yo‘q'});
app.get('/health',wrap(async(req,res)=>{await query('SELECT 1');res.json({ok:true,release:'telegram-management-v1',tests:bank.length,questions:bank.reduce((n,q)=>n+q.questions.length,0)})}));
const TELEGRAM_ADMIN_URL='https://att2026-platform.onrender.com/admin';
await query("CREATE TABLE IF NOT EXISTS telegram_settings(id INTEGER PRIMARY KEY CHECK(id=1),chat_id TEXT,pair_hash TEXT,pair_expires TIMESTAMPTZ); INSERT INTO telegram_settings(id) VALUES(1) ON CONFLICT DO NOTHING");
await query("ALTER TABLE telegram_settings ADD COLUMN IF NOT EXISTS webhook_secret TEXT; ALTER TABLE telegram_settings ADD COLUMN IF NOT EXISTS webhook_enabled BOOLEAN NOT NULL DEFAULT FALSE; CREATE TABLE IF NOT EXISTS telegram_links(user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,telegram_id TEXT UNIQUE NOT NULL,created_at TIMESTAMPTZ DEFAULT now()); CREATE TABLE IF NOT EXISTS telegram_link_codes(user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,code_hash TEXT UNIQUE NOT NULL,expires TIMESTAMPTZ NOT NULL); CREATE TABLE IF NOT EXISTS telegram_updates(update_id BIGINT PRIMARY KEY,created_at TIMESTAMPTZ DEFAULT now())");
const botConfigured=()=>/^\d+:[A-Za-z0-9_-]+$/.test(process.env.TELEGRAM_BOT_TOKEN||'');
async function telegramChat(){const row=(await query('SELECT chat_id FROM telegram_settings WHERE id=1')).rows[0];const id=row?.chat_id||process.env.TELEGRAM_CHAT_ID||'';return /^-?\d+$/.test(id)?id:null;}
async function telegramCall(method,body){
 if(!botConfigured())return null;
 try{
  const response=await fetch('https://api.telegram.org/bot'+process.env.TELEGRAM_BOT_TOKEN+'/'+method,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(6500)});
  const result=await response.json();
  if(!response.ok||!result.ok){console.warn('Telegram request not delivered: HTTP '+response.status);return null;}
  return result.result;
 }catch(e){console.warn('Telegram request failed');return null;}
}
async function telegramNotify(message){
 const chat=await telegramChat();if(!chat||!botConfigured())return false;
 return !!await telegramCall('sendMessage',{chat_id:chat,text:message,disable_web_page_preview:true});
}
const BOT_SITE='https://att2026-platform.onrender.com';
const telegramSend=async(chat,text,keyboard)=>telegramCall('sendMessage',{chat_id:chat,text:String(text).slice(0,3900),disable_web_page_preview:true,...(keyboard?{reply_markup:{keyboard,resize_keyboard:true}}:{})});
const adminKeyboard=[['📩 So‘rovlar','👥 Foydalanuvchilar'],['📊 Statistika','🟢 Online'],['📝 Test natijalari','📅 Kunlik hisobot'],['⚙️ Admin panel','👤 Mening hisobim']];
const userKeyboard=[['👤 Mening hisobim','📝 Test natijalari'],['🌐 Sayt','📞 Admin bilan aloqa'],['ℹ️ Yordam']];
const telegramSettings=async()=>(await query('SELECT webhook_secret,webhook_enabled FROM telegram_settings WHERE id=1')).rows[0];
app.post('/api/admin/notifications/enable-bot',auth,admin,wrap(async(req,res)=>{
 if(!fullAdmin(req.user))return deny(res);
 if(!botConfigured())return res.status(400).json({error:'Bot tokeni sozlanmagan'});
 const row=await telegramSettings(),secret=row.webhook_secret||token();
 await query('UPDATE telegram_settings SET webhook_secret=$1 WHERE id=1',[secret]);
 const ok=await telegramCall('setWebhook',{url:BOT_SITE+'/telegram/webhook',secret_token:secret,allowed_updates:['message']});
 if(!ok)return res.status(502).json({error:'Telegram webhook sozlanmadi'});
 await query('UPDATE telegram_settings SET webhook_enabled=TRUE WHERE id=1');res.json({ok:true});
}));
app.get('/api/telegram/link',auth,wrap(async(req,res)=>{
 const linked=(await query('SELECT 1 FROM telegram_links WHERE user_id=$1',[req.user.id])).rowCount>0;
 res.json({linked,enabled:(await telegramSettings()).webhook_enabled});
}));
app.post('/api/telegram/link',auth,wrap(async(req,res)=>{
 if(!(await telegramSettings()).webhook_enabled)return res.status(400).json({error:'Admin avval bot menyusini faollashtirishi kerak'});
 const bot=await telegramCall('getMe',{});if(!bot?.is_bot||!/^\w{5,32}$/.test(bot.username||''))return res.status(502).json({error:'Bot bilan aloqa yo‘q'});
 const code=randomBytes(12).toString('hex');
 await query("INSERT INTO telegram_link_codes(user_id,code_hash,expires) VALUES($1,$2,now()+interval '10 minutes') ON CONFLICT(user_id) DO UPDATE SET code_hash=excluded.code_hash,expires=excluded.expires",[req.user.id,hash(code)]);
 res.json({command:'/link '+code,bot_username:bot.username});
}));
app.delete('/api/telegram/link',auth,wrap(async(req,res)=>{
 await query('DELETE FROM telegram_links WHERE user_id=$1',[req.user.id]);await query('DELETE FROM telegram_link_codes WHERE user_id=$1',[req.user.id]);res.json({ok:true});
}));
async function telegramNewRequest(name,email){
 const group=await telegramChat();
 const {rows}=await query("SELECT l.telegram_id,u.role,u.is_owner,u.permissions FROM telegram_links l JOIN users u ON u.id=l.user_id WHERE u.active AND u.role='admin'");
 const admins=rows.filter(u=>allowed(u,'user_block'));
 for(const u of admins)await telegramSend(u.telegram_id,'🔔 Yangi kirish so‘rovi!\nIsm: '+name+'\nEmail: '+email+'\nSo‘rovlar: /requests\n'+TELEGRAM_ADMIN_URL);
 if(group&&!admins.some(u=>u.telegram_id===group))await telegramNotify('🔔 ATT2026: yangi kirish so‘rovi!\nAdmin panelda tasdiqlash kutilmoqda.\n'+TELEGRAM_ADMIN_URL);
}
async function botCommand(message){
 const chat=String(message.chat?.id||''),from=String(message.from?.id||''),text=String(message.text||'').trim();
 if(!/^-?\d+$/.test(chat)||!text||message.from?.is_bot)return;
 const pair=text.match(/^\/pair(?:@[A-Za-z0-9_]{5,32})? ([a-f0-9]{24})$/i);
 if(pair&&['private','group','supergroup'].includes(message.chat.type)){
  const r=await query("UPDATE telegram_settings SET chat_id=$1,pair_hash=NULL,pair_expires=NULL WHERE id=1 AND pair_hash=$2 AND pair_expires>now() RETURNING id",[chat,hash(pair[1])]);
  if(r.rowCount)await telegramSend(chat,'✅ ATT2026 bildirishnomalari bog‘landi.');return;
 }
 if(message.chat?.type!=='private'||chat!==from)return; // No account data or administrative commands in public chats.
 const link=text.match(/^\/link(?:@[A-Za-z0-9_]{5,32})? ([a-f0-9]{24})$/i);
 if(link){
  const c=await query("WITH used AS (DELETE FROM telegram_link_codes WHERE code_hash=$1 AND expires>now() RETURNING user_id), linked AS (INSERT INTO telegram_links(user_id,telegram_id) SELECT u.id,$2 FROM used JOIN users u ON u.id=used.user_id WHERE u.active ON CONFLICT DO NOTHING RETURNING user_id) SELECT user_id FROM linked",[hash(link[1]),from]);
  await telegramSend(chat,c.rowCount?'✅ Hisob bog‘landi. /menu buyrug‘ini yuboring.':'Kod noto‘g‘ri, eskirgan yoki hisob avval bog‘langan. Saytdan yangi kod oling.');return;
 }
 const u=(await query('SELECT u.id,u.name,u.email,u.role,u.is_owner,u.permissions FROM telegram_links l JOIN users u ON u.id=l.user_id WHERE l.telegram_id=$1 AND u.active',[from])).rows[0];
 if(!u){await telegramSend(chat,'ATT2026 botiga xush kelibsiz!\nSayt: '+BOT_SITE+'\nHisobingizga kirib Telegram hisobni bog‘lash tugmasini bosing.',[['🌐 Sayt']]);return;}
 const labels={'📩 So‘rovlar':'/requests','👥 Foydalanuvchilar':'/users','📊 Statistika':'/stats','🟢 Online':'/online','📝 Test natijalari':'/results','📅 Kunlik hisobot':'/daily','⚙️ Admin panel':'/admin','👤 Mening hisobim':'/me','🌐 Sayt':'/site','📞 Admin bilan aloqa':'/contact','ℹ️ Yordam':'/help'};
 const parts=(labels[text]||text).split(/\s+/),cmd=parts[0].split('@')[0].toLowerCase(),id=parts[1],device=parts[2];
 const isAdmin=u.role==='admin',menu=isAdmin?adminKeyboard:userKeyboard;
 const send=t=>telegramSend(chat,t,menu),validId=v=>/^\d{1,18}$/.test(v||'');
 const scope=fullAdmin(u);
 if(['/start','/menu','/help'].includes(cmd)){await send(isAdmin?'ATT2026 · Admin menyusi\n/approve ID — tasdiqlash (email egasini oldin tekshiring)\n/reject ID — rad etish\n/block ID — bloklash\n/unblock ID — faollashtirish\n/devices ID — brauzerlar\n/close ID DEVICE_ID — sessiyani yopish\n/admin — sayt boshqaruvi':'ATT2026 · Foydalanuvchi menyusi\n/me — hisob\n/results — o‘z test natijalari\n/site — sayt');return;}
 if(cmd==='/site'){await send(BOT_SITE);return;}
 if(cmd==='/contact'){await send('Murojaat uchun: https://t.me/IC3_masterUz');return;}
 if(cmd==='/me'){await send('👤 '+u.name+'\nEmail: '+u.email+'\nRol: '+(u.is_owner?'Asosiy administrator':scope?'To‘liq administrator':isAdmin?'Administrator':'Foydalanuvchi'));return;}
 if(cmd==='/admin'&&isAdmin){await send(TELEGRAM_ADMIN_URL);return;}
 if(cmd==='/results'){
  if(isAdmin&&allowed(u,'view_results')){
   const {rows}=await query("SELECT u.name,u.email,a.score,a.total FROM attempts a JOIN users u ON u.id=a.user_id WHERE a.finished_at IS NOT NULL AND ($1 OR u.role='student') ORDER BY a.finished_at DESC LIMIT 15",[scope]);
   await send('So‘nggi yakunlangan testlar:\n'+(rows.map(x=>x.name+' · '+x.email+' · '+x.score+'/'+x.total).join('\n')||'Natijalar yo‘q'));
  }else{const {rows}=await query('SELECT quiz_id,score,total FROM attempts WHERE user_id=$1 AND finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 15',[u.id]);await send('Mening test natijalarim:\n'+(rows.map(x=>x.quiz_id+': '+x.score+'/'+x.total).join('\n')||'Natijalar yo‘q'));}
  return;
 }
 if(!isAdmin){await send('Bu buyruq uchun administrator huquqi kerak. /menu');return;}
 if(cmd==='/requests'&&allowed(u,'user_block')){const {rows}=await query("SELECT id,name,email FROM users WHERE pending AND NOT active AND role='student' ORDER BY created_at DESC LIMIT 20");await send('Kutilayotgan so‘rovlar:\n'+(rows.map(x=>'#'+x.id+' · '+x.name+' · '+x.email).join('\n')||'So‘rov yo‘q')+'\n\nEmail egasini tekshirgach: /approve ID yoki /reject ID');return;}
 if(cmd==='/users'){const {rows}=await query("SELECT id,name,email,active FROM users WHERE ($1 OR role='student') ORDER BY created_at DESC LIMIT 20",[scope]);await send('Hisoblar:\n'+(rows.map(x=>'#'+x.id+' · '+x.name+' · '+x.email+' · '+(x.active?'Faol':'Faol emas')).join('\n')||'Hisob yo‘q'));return;}
 if((cmd==='/stats'||cmd==='/daily')&&allowed(u,'view_results')){const {rows}=await query("SELECT count(*) AS tests,COALESCE(round(avg(100.0*a.score/NULLIF(a.total,0))),0) AS average FROM attempts a JOIN users u ON u.id=a.user_id WHERE a.finished_at IS NOT NULL AND ($1 OR u.role='student') AND (NOT $2 OR a.finished_at>now()-interval '24 hours')",[scope,cmd==='/daily']);await send((cmd==='/daily'?'Oxirgi 24 soat':'Umumiy')+' statistikasi\nYakunlangan testlar: '+rows[0].tests+'\nO‘rtacha natija: '+rows[0].average+'%');return;}
 if(cmd==='/online'&&allowed(u,'view_devices')){const {rows}=await query("SELECT DISTINCT u.name,u.email FROM users u JOIN devices d ON d.user_id=u.id JOIN sessions s ON s.device_id=d.id WHERE u.active AND s.expires>now() AND d.last_seen>now()-interval '2 minutes' AND ($1 OR u.role='student') LIMIT 30",[scope]);await send('Online: '+rows.length+'\n'+rows.map(x=>x.name+' · '+x.email).join('\n'));return;}
 if(['/approve','/reject','/block','/unblock','/devices','/close'].includes(cmd)&&validId(id)){
  const target=(await query('SELECT id,role,is_owner,permissions,active,pending FROM users WHERE id=$1',[id])).rows[0];
  if(!target||!manageable(u,target)){await send('Hisob topilmadi yoki himoyalangan.');return;}
  if(cmd==='/devices'&&allowed(u,'view_devices')){const {rows}=await query('SELECT d.id,d.label,EXISTS(SELECT 1 FROM sessions s WHERE s.device_id=d.id AND s.expires>now()) AS active FROM devices d WHERE d.user_id=$1 LIMIT 20',[id]);await send('Brauzerlar:\n'+(rows.map(x=>'#'+x.id+' · '+x.label+' · '+(x.active?'Faol':'Yopilgan')).join('\n')||'Brauzer yo‘q'));return;}
  if(cmd==='/close'&&allowed(u,'manage_sessions')&&validId(device)){const r=await query("DELETE FROM sessions s USING users t WHERE s.user_id=t.id AND t.id=$1 AND s.device_id=$2 AND NOT t.is_owner AND ($3 OR t.role='student' OR ($4 AND NOT (t.permissions ? 'full_admin'))) RETURNING s.device_id",[id,device,u.is_owner,scope]);await activity(u.id,'telegram_session_revoked','Hisob '+id);await send(r.rowCount?'Sessiya yopildi.':'Faol sessiya topilmadi.');return;}
  if(allowed(u,'user_block')&&['/approve','/reject','/block','/unblock'].includes(cmd)){
   if((cmd==='/approve'||cmd==='/reject')&&!target.pending){await send('Bu hisob tasdiqlashni kutmayapti.');return;}
   const active=cmd==='/approve'||cmd==='/unblock';
   const r=await query("UPDATE users SET active=$1,pending=FALSE WHERE id=$2 AND NOT is_owner AND ($3 OR role='student' OR ($4 AND NOT (permissions ? 'full_admin'))) AND (NOT $5 OR pending) RETURNING id",[active,id,u.is_owner,scope,cmd==='/approve'||cmd==='/reject']);
   if(!r.rowCount){await send('Hisob o‘zgarmadi.');return;}
   if(!active)await query('DELETE FROM sessions WHERE user_id=$1',[id]);
   await activity(u.id,'telegram_'+cmd.slice(1),'Hisob '+id);await send('✅ Hisob holati yangilandi.');return;
  }
 }
 await send('Buyruq topilmadi yoki ruxsat yo‘q. /menu');
}
app.post('/telegram/webhook',wrap(async(req,res)=>{
 const settings=await telegramSettings(),provided=req.get('X-Telegram-Bot-Api-Secret-Token');
 if(!settings.webhook_secret||provided!==settings.webhook_secret)return res.sendStatus(403);
 const id=req.body?.update_id;
 if(!Number.isSafeInteger(id)||id<0)return res.sendStatus(400);
 const r=await query('INSERT INTO telegram_updates(update_id) VALUES($1) ON CONFLICT DO NOTHING RETURNING update_id',[id]);
 res.sendStatus(200);
 if(r.rowCount&&req.body.message)void botCommand(req.body.message).catch(()=>console.warn('Telegram command failed'));
}));
app.get('/api/admin/notifications',auth,admin,wrap(async(req,res)=>{
 if(!fullAdmin(req.user))return deny(res);
 const n=(await query('SELECT count(*) AS n FROM users WHERE pending AND NOT active')).rows[0].n;
 res.json({telegram_configured:botConfigured()&&!!await telegramChat(),bot_configured:botConfigured(),webhook_enabled:(await telegramSettings()).webhook_enabled,pending:Number(n)});
}));
app.post('/api/admin/notifications/test',auth,admin,wrap(async(req,res)=>{
 if(!fullAdmin(req.user))return deny(res);
 if(!botConfigured()||!await telegramChat())return res.status(400).json({error:'Bot tokeni yoki Telegram chat bog‘lanmagan'});
 const n=(await query('SELECT count(*) AS n FROM users WHERE pending AND NOT active')).rows[0].n;
 if(!await telegramNotify('✅ ATT2026 bildirishnoma sinovi\nTasdiqlash kutilayotgan so‘rovlar: '+n+'\n'+TELEGRAM_ADMIN_URL))return res.status(502).json({error:'Telegram xabari yuborilmadi. Bot tokeni va botga /start yuborilganini tekshiring.'});
 res.json({ok:true});
}));
app.post('/api/admin/notifications/pair',auth,admin,wrap(async(req,res)=>{
 if(!fullAdmin(req.user))return deny(res);
 if(!botConfigured())return res.status(400).json({error:'Render’da TELEGRAM_BOT_TOKEN sozlanmagan'});
 const bot=await telegramCall('getMe',{});
 if(!bot||!bot.is_bot||!/^\w{5,32}$/.test(bot.username||''))return res.status(502).json({error:'Telegram bot tokenini tekshiring'});
 const code=randomBytes(12).toString('hex');
 await query("UPDATE telegram_settings SET pair_hash=$1,pair_expires=now()+interval '10 minutes' WHERE id=1",[hash(code)]);
 res.json({command:'/pair@'+bot.username+' '+code,bot_username:bot.username});
}));
app.post('/api/admin/notifications/confirm-pair',auth,admin,wrap(async(req,res)=>{
 if(!fullAdmin(req.user))return deny(res);
 if((await telegramSettings()).webhook_enabled){const p=(await query('SELECT pair_hash,chat_id FROM telegram_settings WHERE id=1')).rows[0];if(!p.pair_hash&&p.chat_id)return res.json({ok:true,delivered:true});return res.status(404).json({error:'Telegramga bog‘lash buyrug‘ini yuboring va yana tekshiring.'});}
 const p=(await query("SELECT pair_hash FROM telegram_settings WHERE id=1 AND pair_expires>now()")).rows[0];
 if(!p?.pair_hash)return res.status(400).json({error:'Bog‘lash kodi eskirgan. Yangi kod yarating.'});
 const updates=await telegramCall('getUpdates',{limit:100,timeout:0,allowed_updates:['message']});
 if(!Array.isArray(updates))return res.status(502).json({error:'Telegram bilan aloqa xatosi. Bot tokenini tekshiring.'});
 const match=updates.map(x=>x.message).filter(Boolean).find(m=>{
  const cmd=String(m.text||'').match(/^\/pair(?:@[A-Za-z0-9_]{5,32})? ([a-f0-9]{24})$/i);
  return cmd&&hash(cmd[1])===p.pair_hash&&['private','group','supergroup'].includes(m.chat?.type)&&/^-?\d+$/.test(String(m.chat?.id));
 });
 if(!match)return res.status(404).json({error:'Botga bog‘lash buyrug‘i hali kelmagan. Telegramga yuboring va yana tekshiring.'});
 const result=await query("UPDATE telegram_settings SET chat_id=$1,pair_hash=NULL,pair_expires=NULL WHERE id=1 AND pair_hash=$2 AND pair_expires>now() RETURNING id",[String(match.chat.id),p.pair_hash]);
 if(!result.rowCount)return res.status(409).json({error:'Bog‘lash kodi o‘zgargan. Qayta urinib ko‘ring.'});
 const delivered=await telegramNotify('✅ ATT2026 admin bildirishnomalari ushbu chatga bog‘landi.\n'+TELEGRAM_ADMIN_URL);
 res.json({ok:true,delivered});
}));
app.post('/api/register',rateLimit({windowMs:60*60*1000,limit:5,standardHeaders:true,legacyHeaders:false,message:{error:'So‘rovlar limiti tugadi. Bir soatdan keyin urinib ko‘ring.'}}),wrap(async(req,res)=>{
 const email=emailNorm(req.body.email),name=String(req.body.name||'').trim(),p=req.body.password;
 if(!emailValid(email)||!name||name.length>120||!passwordValid(p)||req.body.consent!==true)return res.status(400).json({error:'Ism, email, 12 belgili parol va rozilik kerak'});
 const r=await query("WITH registered AS (INSERT INTO users(email,name,password_hash,active,pending) VALUES($1,$2,$3,FALSE,TRUE) ON CONFLICT DO NOTHING RETURNING id), logged AS (INSERT INTO activity(user_id,kind,detail) SELECT id,'registration_requested','Kirish so‘rovi' FROM registered RETURNING user_id) SELECT id FROM registered",[email,name,passwordHash(p)]);
 res.json({ok:true,message:'So‘rov ko‘rib chiqiladi. Yangi emailingiz bo‘lsa, u admin panelda kutilayotgan so‘rovlar ro‘yxatida ko‘rinadi. Oldin hisob ochilgan bo‘lsa, admin bilan bog‘laning.'});
 // The registration response never waits for an external notification.
 if(r.rowCount)void telegramNewRequest(name,email).catch(()=>console.warn('Telegram notification failed; registration saved'));
}));
function deviceLabel(ua){
 const s=String(ua||'');
 const os=/Android/i.test(s)?'Android':/iPhone|iPad/i.test(s)?'iOS':/Windows/i.test(s)?'Windows':/Macintosh|Mac OS/i.test(s)?'macOS':/Linux/i.test(s)?'Linux':'Noma’lum OS';
 const device=/iPad|Tablet/i.test(s)?'Planshet':/Mobile|Android|iPhone/i.test(s)?'Telefon':'Kompyuter';
 const browser=/Edg/i.test(s)?'Edge':/OPR|Opera/i.test(s)?'Opera':/Firefox/i.test(s)?'Firefox':/Chrome|CriOS/i.test(s)?'Chrome':/Safari/i.test(s)?'Safari':'Noma’lum brauzer';
 return [device,os,browser].join(' · ');
}
app.post('/api/login',rateLimit({windowMs:15*60*1000,limit:20,standardHeaders:true,legacyHeaders:false,message:{error:'Juda ko‘p urinish. Keyinroq qayta urinib ko‘ring.'}}),wrap(async(req,res)=>{
 const email=emailNorm(req.body.email),p=req.body.password;if(!emailValid(email)||typeof p!=='string'||p.length>128)return res.status(400).json({error:'Email yoki parol xato'});
 const client=await db.connect();let u,device=cookie(req,'att_device'),session=token();
 if(!/^[a-f0-9]{64}$/.test(device))device=token();
 try{
  await client.query('BEGIN');
  u=(await client.query('SELECT * FROM users WHERE email=$1 FOR UPDATE',[email])).rows[0];
  if(!u||!checkPassword(p,u.password_hash)){await client.query('ROLLBACK');return res.status(401).json({error:'Email yoki parol xato'});}
  if(!u.active){await client.query('ROLLBACK');return res.status(403).json({error:u.pending?'Admin tasdiqlashini kuting':'Hisob bloklangan'});}
  const dHash=hash(device);
  await client.query('DELETE FROM sessions WHERE user_id=$1 AND expires<=now()',[u.id]);
  const current=(await client.query("SELECT count(DISTINCT s.device_id) AS n FROM sessions s JOIN devices d ON d.id=s.device_id WHERE s.user_id=$1 AND s.expires>now() AND d.device_hash<>$2",[u.id,dHash])).rows[0];
  if(!fullAdmin(u)&&Number(current.n)>=u.device_limit){await client.query('ROLLBACK');return res.status(409).json({error:'Faol qurilma limiti to‘ldi. Boshqa brauzerdan chiqing yoki admindan sessiyani yopishni so‘rang.'});}
  const d=(await client.query('INSERT INTO devices(user_id,device_hash,label) VALUES($1,$2,$3) ON CONFLICT(user_id,device_hash) DO UPDATE SET last_seen=now(),label=excluded.label RETURNING id',[u.id,dHash,deviceLabel(req.get('user-agent'))])).rows[0];
  await client.query('DELETE FROM sessions WHERE user_id=$1 AND device_id=$2',[u.id,d.id]);
  await client.query("INSERT INTO sessions VALUES($1,$2,$3,now()+interval '7 days')",[hash(session),u.id,d.id]);
  await client.query('COMMIT');
 }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
 res.cookie('att_session',session,{...cookieSettings,maxAge:7*86400000});res.cookie('att_device',device,{...cookieSettings,maxAge:365*86400000});
 await activity(u.id,'login','Hisobga kirish');res.json({name:u.name,email:u.email,role:u.role});
}));
app.get('/api/me',auth,(req,res)=>res.json(req.user));
app.post('/api/logout',auth,wrap(async(req,res)=>{await query('DELETE FROM sessions WHERE token_hash=$1',[hash(cookie(req,'att_session'))]);await activity(req.user.id,'logout','Hisobdan chiqish');res.clearCookie('att_session',cookieSettings);res.json({ok:true})}));
app.get('/api/scores',auth,wrap(async(req,res)=>{const {rows}=await query('SELECT quiz_id,MAX(ROUND(100.0*score/NULLIF(total,0))) AS best FROM attempts WHERE user_id=$1 AND finished_at IS NOT NULL GROUP BY quiz_id',[req.user.id]);res.json(Object.fromEntries(rows.map(r=>[r.quiz_id,Number(r.best)])))}));
app.post('/api/attempts',auth,wrap(async(req,res)=>{const q=quizMap.get(req.body.quiz_id);if(!q)return res.status(400).json({error:'Test topilmadi'});const r=await query('INSERT INTO attempts(user_id,quiz_id,total) VALUES($1,$2,$3) RETURNING id',[req.user.id,q.id,q.questions.length]);await activity(req.user.id,'test_started',q.title);res.json({id:r.rows[0].id})}));
app.post('/api/attempts/:id/finish',auth,wrap(async(req,res)=>{const a=(await query('SELECT * FROM attempts WHERE id=$1 AND user_id=$2',[req.params.id,req.user.id])).rows[0];if(!a)return res.status(404).json({error:'Test topilmadi'});if(a.finished_at)return res.json({score:a.score,total:a.total});const q=quizMap.get(a.quiz_id),answers=req.body.answers;if(!q||!Array.isArray(answers)||answers.length!==q.questions.length||answers.some((x,i)=>!Number.isInteger(x)||x< -1||x>=q.questions[i].options.length))return res.status(400).json({error:'Javoblar noto‘g‘ri'});const score=answers.reduce((n,x,i)=>n+Number(x===q.questions[i].correct),0);const r=await query('UPDATE attempts SET finished_at=now(),score=$1,answers=$2 WHERE id=$3 AND finished_at IS NULL RETURNING id',[score,JSON.stringify(answers),a.id]);if(r.rowCount)await activity(req.user.id,'test_finished',q.title);res.json({score,total:q.questions.length})}));
app.get('/api/admin/users',auth,admin,wrap(async(req,res)=>{
 const {rows}=await query("SELECT u.id,u.name,u.email,u.active,u.role,u.is_owner,u.permissions,u.pending,u.device_limit,u.created_at,(SELECT count(*) FROM devices d WHERE d.user_id=u.id) AS devices,(SELECT count(*) FROM attempts a WHERE a.user_id=u.id AND a.finished_at IS NOT NULL) AS completed,(SELECT max(last_seen) FROM devices d WHERE d.user_id=u.id) AS last_seen,EXISTS(SELECT 1 FROM devices d JOIN sessions s ON s.device_id=d.id WHERE d.user_id=u.id AND s.expires>now() AND d.last_seen>now()-interval '2 minutes') AS online FROM users u WHERE ($1 OR u.role='student') ORDER BY u.created_at DESC",[fullAdmin(req.user)]);
 res.json(rows.map(u=>{if(!allowed(req.user,'view_devices')){u.devices=null;u.online=null;u.last_seen=null;}if(!allowed(req.user,'view_results'))u.completed=null;return u;}));
}));
app.post('/api/admin/users',auth,admin,wrap(async(req,res)=>{
 const email=emailNorm(req.body.email),password=req.body.password,name=String(req.body.name||'').trim(),role=req.body.role??'student',permissions=req.body.permissions??[];
 if(!['student','admin'].includes(role)||!validPermissions(permissions)||!emailValid(email)||!passwordValid(password)||!name||name.length>120)return res.status(400).json({error:'Ism, email, rol va kamida 12 belgili parol kerak'});
 if(role==='admin'?!fullAdmin(req.user):!allowed(req.user,'user_create'))return deny(res);
 if(permissions.includes('full_admin')&&!req.user.is_owner)return deny(res);
 const r=await query('INSERT INTO users(email,name,password_hash,role,permissions) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id',[email,name,passwordHash(password),role,JSON.stringify(role==='admin'?permissions:[])]);
 if(!r.rowCount)return res.status(409).json({error:'Email mavjud'});await activity(req.user.id,'account_created',role+': '+email);res.json({id:r.rows[0].id});
}));
app.patch('/api/admin/users/:id',auth,admin,wrap(async(req,res)=>{
 const id=req.params.id,b=req.body,u=(await query("SELECT * FROM users WHERE id=$1 AND NOT is_owner",[id])).rows[0];
 if(!u||!manageable(req.user,u))return res.status(404).json({error:'Hisob topilmadi yoki himoyalangan'});
 if(Object.keys(b).some(k=>!['email','name','active','password','permissions','device_limit'].includes(k)))return res.status(400).json({error:'Noto‘g‘ri maydon'});
 if(u.role==='admin'&&!fullAdmin(req.user))return deny(res);
 if(b.permissions!==undefined&&(!fullAdmin(req.user)||u.role!=='admin'||!validPermissions(b.permissions)||(b.permissions.includes('full_admin')&&!req.user.is_owner)))return deny(res);
 if((b.email!==undefined||b.name!==undefined)&&!allowed(req.user,'user_edit'))return deny(res);
 if(b.active!==undefined&&!allowed(req.user,'user_block'))return deny(res);
 if(b.device_limit!==undefined&&(!allowed(req.user,'manage_sessions')||!Number.isInteger(b.device_limit)||b.device_limit<1||b.device_limit>20))return deny(res);
 if(b.password!==undefined&&!allowed(req.user,'user_password'))return deny(res);
 const email=b.email===undefined?u.email:emailNorm(b.email),name=b.name===undefined?u.name:String(b.name).trim(),active=b.active===undefined?u.active:b.active,p=b.password;
 if(!emailValid(email)||!name||name.length>120||typeof active!=='boolean'||(p!==undefined&&!passwordValid(p)))return res.status(400).json({error:'Ma’lumotlar xato'});
 await query('UPDATE users SET email=$1,name=$2,active=$3,password_hash=$4,permissions=$5, pending=CASE WHEN $3 THEN FALSE ELSE pending END,device_limit=$8 WHERE id=$6 AND NOT is_owner AND ($7 OR role=\'student\' OR ($9 AND NOT (permissions ? \'full_admin\'))) ',[email,name,active,p?passwordHash(p):u.password_hash,JSON.stringify(b.permissions??u.permissions),id,req.user.is_owner,b.device_limit??u.device_limit,fullAdmin(req.user)]);
 if(!active||p||email!==u.email||b.permissions!==undefined||b.device_limit!==undefined)await query('DELETE FROM sessions WHERE user_id=$1',[id]);
 await activity(req.user.id,'account_updated',email+' · '+Object.keys(b).join(', '));res.json({ok:true});
}));
app.delete('/api/admin/users/:id',auth,admin,wrap(async(req,res)=>{
 if(!allowed(req.user,'user_delete'))return deny(res);
 const r=await query("DELETE FROM users WHERE id=$1 AND NOT is_owner AND ($2 OR role='student' OR ($3 AND NOT (permissions ? 'full_admin'))) RETURNING email",[req.params.id,req.user.is_owner,fullAdmin(req.user)]);
 if(!r.rowCount)return res.status(404).json({error:'Hisob topilmadi'});
 await activity(req.user.id,'account_deleted',r.rows[0].email);res.json({ok:true});
}));
app.get('/api/admin/users/:id',auth,admin,wrap(async(req,res)=>{
 const id=req.params.id;const exists=await query("SELECT 1 FROM users WHERE id=$1 AND ($2 OR role='student')",[id,fullAdmin(req.user)]);
 if(!exists.rowCount)return res.status(404).json({error:'Hisob topilmadi'});
 if(!['view_devices','view_results','view_activity','manage_sessions'].some(p=>allowed(req.user,p)))return deny(res);
 const [devices,attempts,events]=await Promise.all([
 (allowed(req.user,'view_devices')||allowed(req.user,'manage_sessions'))?query('SELECT d.id,d.label,d.first_seen,d.last_seen,EXISTS(SELECT 1 FROM sessions s WHERE s.device_id=d.id AND s.expires>now()) AS session_active FROM devices d WHERE d.user_id=$1 ORDER BY d.last_seen DESC',[id]):{rows:[]},
 allowed(req.user,'view_results')?query('SELECT id,quiz_id,started_at,finished_at,score,total FROM attempts WHERE user_id=$1 ORDER BY started_at DESC LIMIT 200',[id]):{rows:[]},
 allowed(req.user,'view_activity')?query('SELECT kind,detail,created_at FROM activity WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200',[id]):{rows:[]}
 ]);res.json({devices:devices.rows,attempts:attempts.rows,activity:events.rows});
}));
app.delete('/api/admin/users/:id/sessions/:device',auth,admin,wrap(async(req,res)=>{
 if(!allowed(req.user,'manage_sessions'))return deny(res);
 const r=await query("DELETE FROM sessions s USING users u WHERE s.user_id=u.id AND u.id=$1 AND s.device_id=$2 AND NOT u.is_owner AND ($3 OR u.role='student' OR ($4 AND NOT (u.permissions ? 'full_admin'))) RETURNING s.device_id",[req.params.id,req.params.device,req.user.is_owner,fullAdmin(req.user)]);
 if(!r.rowCount)return res.status(404).json({error:'Faol sessiya topilmadi'});
 await activity(req.user.id,'session_revoked','Hisob '+req.params.id+' · brauzer profili '+req.params.device);res.json({ok:true});
}));
app.get('/admin',auth,admin,(req,res)=>res.sendFile(new URL('./admin.html',import.meta.url).pathname));
app.get('/',(req,res)=>res.type('html').send(html));
app.get('/main.js',(req,res)=>res.sendFile(new URL('./main.js',import.meta.url).pathname));
app.use((err,req,res,next)=>{console.error(err.code||err.name);res.status(err.code==='23505'?409:500).json({error:err.code==='23505'?'Email mavjud':'Server xatosi'})});
app.listen(Number(process.env.PORT||3000),'0.0.0.0');
