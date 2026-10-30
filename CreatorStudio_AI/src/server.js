import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { google } from 'googleapis';
import mime from 'mime-types';
import ffmpegPath from 'ffmpeg-static';
import { spawn } from 'node:child_process';
import { createReadStream, mkdirSync, existsSync, unlinkSync } from 'node:fs';
import { randomUUID, createCipheriv, createDecipheriv, createHmac, createHash, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const app = express();
const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL?.includes('render.com') || process.env.DATABASE_URL?.includes('neon.tech') ? { rejectUnauthorized: false } : undefined });
const PgStore = connectPgSimple(session);
const uploadDir = path.resolve(process.env.UPLOAD_DIR || path.join(root, 'uploads'));
const maxUploadBytes = Number(process.env.MAX_UPLOAD_MB || 2048) * 1024 * 1024;
mkdirSync(uploadDir, { recursive: true });

if (!process.env.SESSION_SECRET || !process.env.TOKEN_ENCRYPTION_KEY) {
  console.warn('Set SESSION_SECRET and TOKEN_ENCRYPTION_KEY in .env before using accounts or social integrations.');
}
if (process.env.NODE_ENV === 'production' && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32 || !process.env.TOKEN_ENCRYPTION_KEY || process.env.TOKEN_ENCRYPTION_KEY.length < 32)) {
  throw new Error('Production requires SESSION_SECRET and TOKEN_ENCRYPTION_KEY values with at least 32 characters.');
}

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new PgStore({ pool, createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'development-only-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 24 * 14 }
}));
app.use(express.static(path.join(root, 'public'), { extensions: ['html'] }));

const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const requireUser = (req, res, next) => req.session.userId ? next() : res.status(401).json({ error: 'Please sign in to continue.' });
const safeUser = u => ({ id: u.id, name: u.name, email: u.email });
const configured = key => Boolean(process.env[key]);
const tokenKey = () => {
  if (!process.env.TOKEN_ENCRYPTION_KEY || process.env.TOKEN_ENCRYPTION_KEY.length < 32) throw new Error('Set TOKEN_ENCRYPTION_KEY to a random value with at least 32 characters.');
  return createHash('sha256').update(process.env.TOKEN_ENCRYPTION_KEY).digest();
};
const encrypt = value => {
  const key = tokenKey();
  const iv = randomUUID().replaceAll('-', '').slice(0, 24);
  const cipher = createCipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
  const body = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return `${iv}.${cipher.getAuthTag().toString('hex')}.${body.toString('base64')}`;
};
const decrypt = value => {
  const [iv, tag, body] = value.split('.');
  const decipher = createDecipheriv('aes-256-gcm', tokenKey(), Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(body, 'base64')), decipher.final()]).toString('utf8');
};
const oauthState = payload => Buffer.from(JSON.stringify(payload)).toString('base64url') + '.' + createHmac('sha256', process.env.SESSION_SECRET || '').update(JSON.stringify(payload)).digest('hex');
const verifyState = token => {
  const [data, signature] = String(token || '').split('.');
  if (!data || !signature) return null;
  const json = Buffer.from(data, 'base64url').toString();
  const expected = createHmac('sha256', process.env.SESSION_SECRET || '').update(json).digest('hex');
  if (expected.length !== signature.length || !timingSafeEqual(Buffer.from(expected), Buffer.from(signature))) return null;
  return JSON.parse(json);
};

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY, project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL, mime_type TEXT NOT NULL, size_bytes BIGINT NOT NULL,
    duration_seconds DOUBLE PRECISION, trim_start DOUBLE PRECISION NOT NULL DEFAULT 0,
    trim_end DOUBLE PRECISION, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE TABLE IF NOT EXISTS social_accounts (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, provider TEXT NOT NULL,
    account_name TEXT NOT NULL DEFAULT '', account_id TEXT NOT NULL DEFAULT '',
    access_token TEXT NOT NULL, refresh_token TEXT, expires_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(user_id, provider)
  );`);
}

app.get('/health', asyncRoute(async (_req, res) => {
  await pool.query('SELECT 1');
  res.json({ ok: true, database: 'connected' });
}));
app.get('/api/config', (_req, res) => res.json({
  youtube: configured('GOOGLE_CLIENT_ID') && configured('GOOGLE_CLIENT_SECRET'),
  instagram: configured('META_APP_ID') && configured('META_APP_SECRET'),
  ai: configured('OPENAI_API_KEY'), maxUploadMB: Number(process.env.MAX_UPLOAD_MB || 2048)
}));
app.get('/api/me', asyncRoute(async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const { rows } = await pool.query('SELECT id,name,email FROM users WHERE id=$1', [req.session.userId]);
  if (!rows[0]) { req.session.destroy(() => {}); return res.json({ user: null }); }
  const accounts = await pool.query('SELECT provider,account_name FROM social_accounts WHERE user_id=$1', [req.session.userId]);
  res.json({ user: safeUser(rows[0]), accounts: accounts.rows });
}));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
app.post('/api/auth/register', authLimiter, asyncRoute(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80);
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (name.length < 2 || !/^\S+@\S+\.\S+$/.test(email) || password.length < 10) return res.status(400).json({ error: 'Enter a name, a valid email, and a password with at least 10 characters.' });
  const id = randomUUID();
  try {
    const { rows } = await pool.query('INSERT INTO users(id,name,email,password_hash) VALUES($1,$2,$3,$4) RETURNING id,name,email', [id, name, email, await bcrypt.hash(password, 12)]);
    req.session.userId = id;
    res.status(201).json({ user: safeUser(rows[0]) });
  } catch (error) { if (error.code === '23505') return res.status(409).json({ error: 'An account already uses that email.' }); throw error; }
}));
app.post('/api/auth/login', authLimiter, asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const { rows } = await pool.query('SELECT id,name,email,password_hash FROM users WHERE email=$1', [email]);
  if (!rows[0] || !await bcrypt.compare(String(req.body.password || ''), rows[0].password_hash)) return res.status(401).json({ error: 'Email or password is incorrect.' });
  await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
  req.session.userId = rows[0].id;
  res.json({ user: safeUser(rows[0]) });
}));
app.post('/api/auth/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/projects', requireUser, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`SELECT p.*, COUNT(a.id)::int AS asset_count,
    COALESCE(SUM(a.size_bytes),0)::bigint AS bytes FROM projects p
    LEFT JOIN assets a ON a.project_id=p.id WHERE p.user_id=$1
    GROUP BY p.id ORDER BY p.updated_at DESC`, [req.session.userId]);
  res.json({ projects: rows });
}));
app.post('/api/projects', requireUser, asyncRoute(async (req, res) => {
  const title = String(req.body.title || 'Untitled video project').trim().slice(0, 160);
  const { rows } = await pool.query('INSERT INTO projects(id,user_id,title,description) VALUES($1,$2,$3,$4) RETURNING *', [randomUUID(), req.session.userId, title || 'Untitled video project', String(req.body.description || '').slice(0, 4000)]);
  res.status(201).json({ project: rows[0] });
}));
app.get('/api/projects/:projectId', requireUser, asyncRoute(async (req, res) => {
  const p = await pool.query('SELECT * FROM projects WHERE id=$1 AND user_id=$2', [req.params.projectId, req.session.userId]);
  if (!p.rows[0]) return res.status(404).json({ error: 'Project not found.' });
  const a = await pool.query('SELECT id,original_name,mime_type,size_bytes,duration_seconds,trim_start,trim_end,created_at FROM assets WHERE project_id=$1 ORDER BY created_at DESC', [req.params.projectId]);
  res.json({ project: p.rows[0], assets: a.rows.map(x => ({ ...x, url: `/api/assets/${x.id}/stream` })) });
}));
app.patch('/api/projects/:projectId', requireUser, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`UPDATE projects SET title=COALESCE($3,title), description=COALESCE($4,description), updated_at=now()
    WHERE id=$1 AND user_id=$2 RETURNING *`, [req.params.projectId, req.session.userId, req.body.title == null ? null : String(req.body.title).trim().slice(0,160), req.body.description == null ? null : String(req.body.description).slice(0,4000)]);
  if (!rows[0]) return res.status(404).json({ error: 'Project not found.' });
  res.json({ project: rows[0] });
}));
app.delete('/api/projects/:projectId', requireUser, asyncRoute(async (req, res) => {
  const files = await pool.query('SELECT stored_name FROM assets WHERE project_id=$1 AND user_id=$2', [req.params.projectId, req.session.userId]);
  const deleted = await pool.query('DELETE FROM projects WHERE id=$1 AND user_id=$2 RETURNING id', [req.params.projectId, req.session.userId]);
  if (!deleted.rows[0]) return res.status(404).json({ error: 'Project not found.' });
  files.rows.forEach(x => removeFile(x.stored_name));
  res.json({ ok: true });
}));

const storage = multer.diskStorage({ destination: (_req, _file, cb) => cb(null, uploadDir), filename: (_req, file, cb) => cb(null, `${randomUUID()}${path.extname(file.originalname).toLowerCase().slice(0,12)}`) });
const fileUpload = multer({ storage, limits: { fileSize: maxUploadBytes, files: 1 }, fileFilter: (_req, file, cb) => cb(null, /^video\//i.test(file.mimetype) || /^audio\//i.test(file.mimetype)) });
const getAsset = async (id, userId) => (await pool.query('SELECT a.*,p.title AS project_title FROM assets a JOIN projects p ON p.id=a.project_id WHERE a.id=$1 AND a.user_id=$2', [id,userId])).rows[0];
const removeFile = file => { try { const p = path.join(uploadDir, path.basename(file)); if (existsSync(p)) unlinkSync(p); } catch {} };
app.post('/api/projects/:projectId/assets', requireUser, (req, res, next) => {
  fileUpload.single('file')(req,res,err => err ? res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? `File is larger than ${process.env.MAX_UPLOAD_MB || 2048} MB.` : err.message }) : next());
}, asyncRoute(async (req, res) => {
  const project = await pool.query('SELECT id FROM projects WHERE id=$1 AND user_id=$2', [req.params.projectId,req.session.userId]);
  if (!project.rows[0]) { if (req.file) removeFile(req.file.filename); return res.status(404).json({ error: 'Project not found.' }); }
  if (!req.file) return res.status(400).json({ error: 'Choose a video or audio file.' });
  const id = randomUUID();
  const duration = Number(req.body.duration);
  const { rows } = await pool.query(`INSERT INTO assets(id,project_id,user_id,original_name,stored_name,mime_type,size_bytes,duration_seconds)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,original_name,mime_type,size_bytes,duration_seconds,trim_start,trim_end,created_at`,
    [id,req.params.projectId,req.session.userId,path.basename(req.file.originalname).slice(0,255),req.file.filename,req.file.mimetype,req.file.size,Number.isFinite(duration)&&duration>0?duration:null]);
  await pool.query('UPDATE projects SET updated_at=now() WHERE id=$1', [req.params.projectId]);
  res.status(201).json({ asset: { ...rows[0], url: `/api/assets/${id}/stream` } });
}));
app.get('/api/assets/:assetId/stream', requireUser, asyncRoute(async (req,res) => {
  const a = await getAsset(req.params.assetId,req.session.userId); if (!a) return res.sendStatus(404);
  const filename = path.join(uploadDir,path.basename(a.stored_name)); if (!existsSync(filename)) return res.status(410).json({ error: 'Media file is missing from storage.' });
  const size=Number(a.size_bytes);const range=req.headers.range;
  if(range){const match=/^bytes=(\d*)-(\d*)$/.exec(range);if(!match||(!match[1]&&!match[2]))return res.status(416).set('Content-Range',`bytes */${size}`).end();let start=match[1]?Number(match[1]):null;let end=match[2]?Number(match[2]):null;if(start===null){const suffix=end;if(!suffix)return res.status(416).set('Content-Range',`bytes */${size}`).end();start=Math.max(0,size-suffix);end=size-1}else end=end===null?size-1:end;if(start>=size||end<start)return res.status(416).set('Content-Range',`bytes */${size}`).end();end=Math.min(end,size-1);res.status(206).type(a.mime_type).set({'Accept-Ranges':'bytes','Content-Range':`bytes ${start}-${end}/${size}`,'Content-Length':String(end-start+1)});return createReadStream(filename,{start,end}).pipe(res)}
  res.type(a.mime_type); res.setHeader('Content-Length',size); res.setHeader('Accept-Ranges','bytes'); createReadStream(filename).pipe(res);
}));
app.patch('/api/assets/:assetId/trim', requireUser, asyncRoute(async (req,res) => {
  const a = await getAsset(req.params.assetId,req.session.userId); if (!a) return res.sendStatus(404);
  const start = Number(req.body.start); const end = Number(req.body.end);
  if (!Number.isFinite(start)||!Number.isFinite(end)||start<0||end<=start||(a.duration_seconds && end>a.duration_seconds+0.15)) return res.status(400).json({ error: 'Enter a valid start and end within the video duration.' });
  await pool.query('UPDATE assets SET trim_start=$1,trim_end=$2 WHERE id=$3',[start,end,a.id]);
  res.json({ ok: true, trim_start:start,trim_end:end });
}));
app.get('/api/assets/:assetId/export', requireUser, asyncRoute(async(req,res)=>{
  const a=await getAsset(req.params.assetId,req.session.userId);if(!a)return res.sendStatus(404);
  const start=Number(req.query.start ?? a.trim_start);const end=Number(req.query.end ?? a.trim_end ?? a.duration_seconds);
  if(!Number.isFinite(start)||!Number.isFinite(end)||start<0||end<=start)return res.status(400).json({error:'Set a valid trim range before exporting.'});
  const filename=path.join(uploadDir,path.basename(a.stored_name));if(!existsSync(filename))return res.status(410).json({error:'Media file is missing from storage.'});
  res.setHeader('Content-Type','video/mp4');res.setHeader('Content-Disposition','attachment; filename="creatorstudio-cut.mp4"');
  const ff=spawn(ffmpegPath,['-hide_banner','-loglevel','error','-ss',String(start),'-i',filename,'-t',String(end-start),'-map','0:v?','-map','0:a?','-c:v','libx264','-preset','veryfast','-crf','22','-c:a','aac','-movflags','frag_keyframe+empty_moov+default_base_moof','-f','mp4','pipe:1']);
  ff.stdout.pipe(res);ff.stderr.on('data',d=>console.error('ffmpeg:',d.toString().slice(0,500)));ff.on('error',e=>{console.error(e);if(!res.headersSent)res.status(500).end('Export failed; check that uploaded file is a supported video.')});ff.on('close',code=>{if(code&& !res.writableEnded)res.end()});
}));
app.delete('/api/assets/:assetId',requireUser,asyncRoute(async(req,res)=>{const a=await getAsset(req.params.assetId,req.session.userId);if(!a)return res.sendStatus(404);await pool.query('DELETE FROM assets WHERE id=$1',[a.id]);removeFile(a.stored_name);res.json({ok:true})}));

app.post('/api/ai/metadata',requireUser,asyncRoute(async(req,res)=>{
  const prompt=String(req.body.prompt||'').trim().slice(0,1200);const title=String(req.body.title||'').slice(0,160);const context=String(req.body.context||'').slice(0,1800);
  if(!prompt)return res.status(400).json({error:'Write a request first.'});
  if(process.env.OPENAI_API_KEY){
    const r=await fetch('https://api.openai.com/v1/chat/completions',{method:'POST',headers:{Authorization:`Bearer ${process.env.OPENAI_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({model:process.env.OPENAI_MODEL||'gpt-4o-mini',temperature:0.7,response_format:{type:'json_object'},messages:[{role:'system',content:'Help a video creator prepare metadata and a simple edit note. Return JSON only with keys reply, title, description, caption, tags. Never claim to modify the video. Fill only helpful fields and use empty strings otherwise.'},{role:'user',content:JSON.stringify({prompt,title,context})}]})});
    const data=await r.json();if(!r.ok) return res.status(502).json({error:data.error?.message||'AI request failed. Check OPENAI_API_KEY.'});
    try{return res.json(JSON.parse(data.choices[0].message.content))}catch{return res.status(502).json({error:'AI returned an unreadable response.'})}
  }
  const p=prompt.toLowerCase();let result={reply:'I can help draft titles, descriptions, captions, tags, and trim instructions. Add OPENAI_API_KEY for open-ended AI suggestions.',title:'',description:'',caption:'',tags:''};
  if(/title|caption|hashtag|description|tag|social|write|hook/.test(p)){const subject=title||context||'your video';result={reply:`Here is a starter draft for “${subject}”. Edit it before publishing.`,title:title||`A fresh look at ${subject}`,description:`In this video: ${subject}. Watch, share your thoughts, and follow for more.`,caption:`A fresh look at ${subject} ✨ What do you think? #creator #video`,tags:'video, creator, tutorial'}};
  if(/trim|cut|silence|short/.test(p))result.reply='Set the Start and End fields below the preview, then choose Save trim and Export clip. I can suggest edits, but the export is controlled by your selected trim points.';
  res.json(result);
}));

function youtubeClient() { return new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID,process.env.GOOGLE_CLIENT_SECRET,process.env.GOOGLE_REDIRECT_URI||`${process.env.APP_URL}/api/oauth/youtube/callback`); }
app.get('/api/oauth/youtube/start',requireUser,(req,res)=>{if(!configured('GOOGLE_CLIENT_ID')||!configured('GOOGLE_CLIENT_SECRET'))return res.status(503).send('Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in environment variables first.');const state=oauthState({u:req.session.userId,p:'youtube',n:randomUUID()});res.redirect(youtubeClient().generateAuthUrl({access_type:'offline',prompt:'consent',scope:['https://www.googleapis.com/auth/youtube.upload','openid','email','profile'],state}));});
app.get('/api/oauth/youtube/callback',asyncRoute(async(req,res)=>{const s=verifyState(req.query.state);if(!s||s.p!=='youtube'||!req.query.code)return res.redirect('/?connection=failed');const {tokens}=await youtubeClient().getToken(String(req.query.code));const client=youtubeClient();client.setCredentials(tokens);const oauth2=google.oauth2({auth:client,version:'v2'});const {data:user}=await oauth2.userinfo.get();const {data:channel}=await google.youtube({version:'v3',auth:client}).channels.list({part:['snippet'],mine:true,maxResults:1});const id=s.u;await pool.query(`INSERT INTO social_accounts(user_id,provider,account_id,account_name,access_token,refresh_token,expires_at) VALUES($1,'youtube',$2,$3,$4,$5,$6) ON CONFLICT(user_id,provider) DO UPDATE SET account_id=EXCLUDED.account_id,account_name=EXCLUDED.account_name,access_token=EXCLUDED.access_token,refresh_token=COALESCE(EXCLUDED.refresh_token,social_accounts.refresh_token),expires_at=EXCLUDED.expires_at,updated_at=now()`,[id,channel.data.items?.[0]?.id||user.id,channel.data.items?.[0]?.snippet?.title||user.name||user.email,encrypt(tokens.access_token||''),tokens.refresh_token?encrypt(tokens.refresh_token):null,tokens.expiry_date?new Date(tokens.expiry_date):null]);res.redirect('/?connection=youtube');}));
app.post('/api/publish/youtube',requireUser,asyncRoute(async(req,res)=>{
  const a=await getAsset(req.body.assetId,req.session.userId);if(!a)return res.status(404).json({error:'Choose a video first.'});
  const account=(await pool.query("SELECT * FROM social_accounts WHERE user_id=$1 AND provider='youtube'",[req.session.userId])).rows[0];if(!account)return res.status(400).json({error:'Connect your YouTube account first.'});
  const client=youtubeClient();client.setCredentials({access_token:decrypt(account.access_token),refresh_token:account.refresh_token?decrypt(account.refresh_token):undefined,expiry_date:account.expires_at?new Date(account.expires_at).getTime():undefined});
  const auth=await client.getAccessToken();if(client.credentials.access_token)await pool.query("UPDATE social_accounts SET access_token=$1,expires_at=$2 WHERE user_id=$3 AND provider='youtube'",[encrypt(client.credentials.access_token),client.credentials.expiry_date?new Date(client.credentials.expiry_date):null,req.session.userId]);
  const yt=google.youtube({version:'v3',auth:client});const title=String(req.body.title||a.original_name).slice(0,100);const response=await yt.videos.insert({part:['snippet','status'],requestBody:{snippet:{title,description:String(req.body.description||'').slice(0,5000),tags:String(req.body.tags||'').split(',').map(x=>x.trim()).filter(Boolean).slice(0,500),categoryId:'22'},status:{privacyStatus:['private','unlisted','public'].includes(req.body.privacy)?req.body.privacy:'private',selfDeclaredMadeForKids:Boolean(req.body.madeForKids)}},media:{body:createReadStream(path.join(uploadDir,path.basename(a.stored_name)))}});
  res.json({ok:true,id:response.data.id,url:`https://www.youtube.com/watch?v=${response.data.id}`});
}));

const graph=(p='')=>`https://graph.facebook.com/${process.env.META_GRAPH_VERSION||'v22.0'}${p}`;
app.get('/api/oauth/instagram/start',requireUser,(req,res)=>{if(!configured('META_APP_ID')||!configured('META_APP_SECRET'))return res.status(503).send('Set META_APP_ID and META_APP_SECRET in environment variables first.');const redirect=process.env.META_REDIRECT_URI||`${process.env.APP_URL}/api/oauth/instagram/callback`;const state=oauthState({u:req.session.userId,p:'instagram',n:randomUUID()});const scope='instagram_basic,instagram_content_publish,pages_show_list,pages_read_engagement';res.redirect(`https://www.facebook.com/${process.env.META_GRAPH_VERSION||'v22.0'}/dialog/oauth?client_id=${encodeURIComponent(process.env.META_APP_ID)}&redirect_uri=${encodeURIComponent(redirect)}&scope=${encodeURIComponent(scope)}&response_type=code&state=${encodeURIComponent(state)}`);});
app.get('/api/oauth/instagram/callback',asyncRoute(async(req,res)=>{const s=verifyState(req.query.state);if(!s||s.p!=='instagram'||!req.query.code)return res.redirect('/?connection=failed');const redirect=process.env.META_REDIRECT_URI||`${process.env.APP_URL}/api/oauth/instagram/callback`;const tokenUrl=new URL(graph('/oauth/access_token'));tokenUrl.search=new URLSearchParams({client_id:process.env.META_APP_ID,client_secret:process.env.META_APP_SECRET,redirect_uri:redirect,code:String(req.query.code)});let r=await fetch(tokenUrl);let data=await r.json();if(!r.ok)throw new Error(data.error?.message||'Instagram authorization failed.');const exchange=new URL(graph('/oauth/access_token'));exchange.search=new URLSearchParams({grant_type:'fb_exchange_token',client_id:process.env.META_APP_ID,client_secret:process.env.META_APP_SECRET,fb_exchange_token:data.access_token});r=await fetch(exchange);const longToken=await r.json();if(r.ok&&longToken.access_token)data=longToken;const token=data.access_token;r=await fetch(graph('/me/accounts?fields=name,instagram_business_account{id,username},access_token'),{headers:{Authorization:`Bearer ${token}`}});data=await r.json();if(!r.ok)throw new Error(data.error?.message||'Could not find an Instagram professional account connected to a Facebook Page.');const page=data.data?.find(x=>x.instagram_business_account);if(!page)throw new Error('Connect an Instagram Creator or Business account to a Facebook Page, then try again.');await pool.query(`INSERT INTO social_accounts(user_id,provider,account_id,account_name,access_token) VALUES($1,'instagram',$2,$3,$4) ON CONFLICT(user_id,provider) DO UPDATE SET account_id=EXCLUDED.account_id,account_name=EXCLUDED.account_name,access_token=EXCLUDED.access_token,updated_at=now()`,[s.u,page.instagram_business_account.id,page.instagram_business_account.username||page.name,encrypt(page.access_token||token)]);res.redirect('/?connection=instagram');}));
app.get('/media/public/:assetId',asyncRoute(async(req,res)=>{const {exp,sig}=req.query;const expected=createHmac('sha256',process.env.SESSION_SECRET||'').update(`${req.params.assetId}:${exp}`).digest('hex');if(Number(exp)<Date.now()||expected.length!==String(sig).length||!timingSafeEqual(Buffer.from(expected),Buffer.from(String(sig))))return res.sendStatus(403);const a=(await pool.query('SELECT * FROM assets WHERE id=$1',[req.params.assetId])).rows[0];if(!a)return res.sendStatus(404);res.type(a.mime_type);res.setHeader('Content-Length',a.size_bytes);createReadStream(path.join(uploadDir,path.basename(a.stored_name))).pipe(res);}));
app.post('/api/publish/instagram',requireUser,asyncRoute(async(req,res)=>{const a=await getAsset(req.body.assetId,req.session.userId);if(!a)return res.status(404).json({error:'Choose a video first.'});const account=(await pool.query("SELECT * FROM social_accounts WHERE user_id=$1 AND provider='instagram'",[req.session.userId])).rows[0];if(!account)return res.status(400).json({error:'Connect Instagram first.'});if(!process.env.APP_URL?.startsWith('https://'))return res.status(400).json({error:'Instagram publishing needs APP_URL set to your public HTTPS Render URL.'});const exp=Date.now()+30*60*1000;const sig=createHmac('sha256',process.env.SESSION_SECRET||'').update(`${a.id}:${exp}`).digest('hex');const videoUrl=`${process.env.APP_URL}/media/public/${a.id}?exp=${exp}&sig=${sig}`;const token=decrypt(account.access_token);let r=await fetch(graph(`/${account.account_id}/media`),{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({media_type:'REELS',video_url:videoUrl,caption:String(req.body.caption||'').slice(0,2200),share_to_feed:String(Boolean(req.body.shareToFeed)),access_token:token})});let data=await r.json();if(!r.ok)throw new Error(data.error?.message||'Instagram could not create a Reel container.');const creationId=data.id;let status='IN_PROGRESS';for(let i=0;i<12&&status==='IN_PROGRESS';i++){await new Promise(resolve=>setTimeout(resolve,5000));r=await fetch(graph(`/${creationId}?fields=status_code,status&access_token=${encodeURIComponent(token)}`));data=await r.json();if(!r.ok)throw new Error(data.error?.message||'Instagram processing check failed.');status=data.status_code||'FINISHED';if(status==='ERROR')throw new Error(data.status||'Instagram could not process this video.');}if(status==='IN_PROGRESS')return res.status(202).json({ok:false,error:'Instagram is still processing the video. Please try publishing again in a moment.'});r=await fetch(graph(`/${account.account_id}/media_publish`),{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({creation_id:creationId,access_token:token})});data=await r.json();if(!r.ok)throw new Error(data.error?.message||'Instagram did not publish the Reel.');res.json({ok:true,id:data.id,url:`https://www.instagram.com/reels/${data.id}/`});}));

app.use((err,_req,res,_next)=>{console.error(err);if(res.headersSent)return;res.status(500).json({error:process.env.NODE_ENV==='production'?'Something went wrong. Check your server logs.':err.message||'Internal server error.'});});
const port=Number(process.env.PORT||3000);
initDb().then(()=>app.listen(port,()=>console.log(`CreatorStudio listening on ${port}`))).catch(error=>{console.error('Database initialization failed:',error);process.exit(1)});
