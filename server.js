'use strict';
require('dotenv').config();
const express      = require('express');
const mongoose     = require('mongoose');
const helmet       = require('helmet');
const cors         = require('cors');
const rateLimit    = require('express-rate-limit');
const jwt          = require('jsonwebtoken');
const bcrypt       = require('bcryptjs');
const multer       = require('multer');
const sharp        = require('sharp');
const path         = require('path');
const fs           = require('fs');
const morgan       = require('morgan');
const mongoSanitize = require('express-mongo-sanitize');
const { body, param, validationResult } = require('express-validator');
const Report = require('./models/Report');
const app  = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);
app.use(helmet());
const allowedOrigins = [process.env.ALLOWED_ORIGIN || 'https://tvarad.ro','http://localhost:3000','http://localhost:5173'];
app.use(cors({ origin: (origin, cb) => { if (!origin || allowedOrigins.includes(origin)) return cb(null, true); cb(new Error('CORS blocked')); }, methods: ['GET','POST','PATCH','DELETE'], allowedHeaders: ['Content-Type','Authorization'], credentials: true }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());
if (process.env.NODE_ENV !== 'production') app.use(morgan('dev'));
const globalLimiter = rateLimit({ windowMs: 15*60*1000, max: 200, standardHeaders: true, legacyHeaders: false });
app.use('/api/', globalLimiter);
const reportLimiter = rateLimit({ windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS)||60000, max: parseInt(process.env.RATE_LIMIT_MAX_REPORTS)||1, keyGenerator: req => req.ip, skip: req => req.method !== 'POST', handler: (req,res) => res.status(429).json({ error: 'Te rugăm să aștepți un minut între raportări.' }), standardHeaders: true, legacyHeaders: false });
const adminLoginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, keyGenerator: req => req.ip, handler: (req,res) => res.status(429).json({ error: 'Prea multe încercări.' }) });
function requireAdmin(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Token lipsă.' });
  try { const d = jwt.verify(h.split(' ')[1], process.env.JWT_SECRET); if (d.role !== 'admin') throw new Error(); req.admin = d; next(); }
  catch { return res.status(401).json({ error: 'Token invalid.' }); }
}
const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5*1024*1024, files: 3 }, fileFilter: (req,file,cb) => { if (['image/jpeg','image/png','image/webp'].includes(file.mimetype)) cb(null,true); else cb(new Error('Doar JPEG/PNG/WebP')); } });
async function processAndStoreImage(file) {
  const { data, info } = await sharp(file.buffer).resize({ width:1280, height:1280, fit:'inside', withoutEnlargement:true }).webp({ quality:75 }).toBuffer({ resolveWithObject:true });
  const filename = `${Date.now()}-${Math.random().toString(36).slice(2)}.webp`;
  fs.writeFileSync(path.join(UPLOAD_DIR, filename), data);
  return { url: `/uploads/${filename}`, publicId: null, width: info.width, height: info.height, sizeKb: Math.round(data.length/1024) };
}
app.use('/uploads', express.static(UPLOAD_DIR));
const VALID_TYPES = ['crack','flood','light','tree','sign','sidewalk','graffiti','waste'];
const validateReport = [ body('type').isIn(VALID_TYPES), body('title').trim().isLength({min:5,max:100}), body('desc').optional().trim().isLength({max:1000}), body('lat').isFloat({min:45.9,max:46.5}), body('lng').isFloat({min:20.8,max:21.8}) ];
function checkValidation(req,res,next) { const e = validationResult(req); if (!e.isEmpty()) return res.status(400).json({ errors: e.array() }); next(); }
app.get('/api/health', (req,res) => res.json({ status:'ok', env: process.env.NODE_ENV, ts: new Date().toISOString() }));
app.get('/api/reports', async (req,res) => {
  try {
    const { status='active', type, limit=100 } = req.query;
    const filter = {};
    if (['active','resolved','all'].includes(status) && status !== 'all') filter.status = status;
    if (type && VALID_TYPES.includes(type)) filter.type = type;
    const reports = await Report.find(filter).sort({ votes:-1, createdAt:-1 }).limit(Math.min(parseInt(limit),200)).select('-reporterIp -voterIps -__v');
    res.json({ count: reports.length, data: reports });
  } catch(err) { res.status(500).json({ error:'Eroare server.' }); }
});
app.post('/api/reports', reportLimiter, upload.array('images',3), validateReport, checkValidation, async (req,res) => {
  try {
    const { type, title, desc, lat, lng } = req.body;
    const pLat = parseFloat(lat), pLng = parseFloat(lng);
    const nearby = await Report.findNearby(pLat, pLng, 20);
    if (nearby.length > 0) return res.status(409).json({ duplicate:true, message:'Există deja un raport în această zonă (20m). Votează raportul existent.', existingReport: { id:nearby[0]._id, title:nearby[0].title, votes:nearby[0].votes, type:nearby[0].type } });
    const imageRecords = [];
    if (req.files && req.files.length > 0) { for (const f of req.files) { try { imageRecords.push(await processAndStoreImage(f)); } catch(e) { console.error(e.message); } } }
    const reporterIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
    const report = await Report.create({ type, title, desc, lat:pLat, lng:pLng, location:{ type:'Point', coordinates:[pLng,pLat] }, images:imageRecords, reporterIp });
    res.status(201).json({ success:true, data:report.toJSON() });
  } catch(err) { console.error(err); res.status(500).json({ error:'Eroare la salvare.' }); }
});
app.patch('/api/reports/:id/vote', param('id').isMongoId(), checkValidation, async (req,res) => {
  try {
    const voterIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    const report = await Report.findById(req.params.id).select('+voterIps');
    if (!report) return res.status(404).json({ error:'Raport negăsit.' });
    const already = report.voterIps.includes(voterIp);
    if (already) { report.voterIps = report.voterIps.filter(ip=>ip!==voterIp); report.votes = Math.max(0,report.votes-1); }
    else { report.voterIps.push(voterIp); report.votes += 1; }
    await report.save();
    res.json({ success:true, votes:report.votes, voted:!already });
  } catch(err) { res.status(500).json({ error:'Eroare vot.' }); }
});
app.post('/api/admin/login', adminLoginLimiter, async (req,res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error:'Parola lipsă.' });
    const hash = process.env.ADMIN_HASH || bcrypt.hashSync(process.env.ADMIN_PASSWORD||'Arad2026', 12);
    const valid = await bcrypt.compare(password, hash);
    if (!valid) return res.status(401).json({ error:'Parolă incorectă.' });
    const token = jwt.sign({ role:'admin', iss:'urbanfix-arad' }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN||'8h' });
    res.json({ success:true, token, expiresIn:'8h' });
  } catch(err) { res.status(500).json({ error:'Eroare server.' }); }
});
app.get('/api/admin/reports', requireAdmin, async (req,res) => {
  try {
    const { status, type } = req.query;
    const filter = {};
    if (status && status !== 'all') filter.status = status;
    if (type && VALID_TYPES.includes(type)) filter.type = type;
    const reports = await Report.find(filter).select('+reporterIp').sort({ votes:-1, createdAt:-1 });
    res.json({ count:reports.length, data:reports });
  } catch(err) { res.status(500).json({ error:'Eroare server.' }); }
});
app.patch('/api/admin/reports/:id/resolve', requireAdmin, param('id').isMongoId(), checkValidation, async (req,res) => {
  try {
    const report = await Report.findByIdAndUpdate(req.params.id, { status:'resolved', resolvedAt:new Date() }, { new:true });
    if (!report) return res.status(404).json({ error:'Raport negăsit.' });
    res.json({ success:true, data:report });
  } catch(err) { res.status(500).json({ error:'Eroare server.' }); }
});
app.delete('/api/admin/reports/:id', requireAdmin, param('id').isMongoId(), checkValidation, async (req,res) => {
  try {
    const report = await Report.findByIdAndDelete(req.params.id);
    if (!report) return res.status(404).json({ error:'Raport negăsit.' });
    res.json({ success:true, message:'Raport șters.' });
  } catch(err) { res.status(500).json({ error:'Eroare server.' }); }
});
app.get('/api/admin/export', requireAdmin, async (req,res) => {
  try {
    const reports = await Report.find().sort({ createdAt:-1 });
    const rows = reports.map(r => ({ ID:r._id.toString(), 'Data':r.createdAt.toISOString().split('T')[0], Categorie:r.type, Titlu:r.title, Descriere:r.desc, Lat:r.lat, Lng:r.lng, Status:r.status==='resolved'?'Rezolvat':'Activ', Voturi:r.votes }));
    res.json({ count:rows.length, data:rows });
  } catch(err) { res.status(500).json({ error:'Eroare export.' }); }
});
app.get('/', (req, res) => {
  const publicDir = path.join(__dirname, 'public');
  const indexFile = path.join(publicDir, 'index.html');
  if (fs.existsSync(indexFile)) {
    res.sendFile(indexFile);
  } else {
    res.send('<h1>UrbanFix Arad</h1><p>Frontend loading...</p>');
  }
});
app.use(express.static(path.join(__dirname, 'public')));

app.use((err,req,res,_next) => { const isDev = process.env.NODE_ENV !== 'production'; res.status(err.status||500).json({ error: isDev ? err.message : 'Eroare internă.' }); });
async function startServer() {
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) { console.error('JWT_SECRET lipsă sau prea scurtă!'); process.exit(1); }
  if (!process.env.MONGODB_URI) { console.error('MONGODB_URI lipsă!'); process.exit(1); }
  try { await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS:5000 }); console.log('✅ MongoDB connected'); app.listen(PORT, () => console.log(`🚀 UrbanFix Arad pe portul ${PORT}`)); }
  catch(err) { console.error('❌ Start failed:', err.message); process.exit(1); }
}
process.on('SIGTERM', async () => { await mongoose.disconnect(); process.exit(0); });
startServer();
