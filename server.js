const express = require('express');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';

const dataDir = path.join(__dirname, 'data');
const uploadDir = path.join(__dirname, 'public', 'uploads');
fs.mkdirSync(dataDir, {recursive:true});
fs.mkdirSync(uploadDir, {recursive:true});

const db = new Database(path.join(dataDir, 'cleancity.db'));
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  phone TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'citizen',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  location TEXT NOT NULL,
  lat REAL,
  lng REAL,
  status TEXT NOT NULL DEFAULT 'Open',
  votes INTEGER NOT NULL DEFAULT 0,
  image TEXT,
  department TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS report_status_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id TEXT NOT NULL,
  status TEXT NOT NULL,
  changed_by INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE,
  FOREIGN KEY(changed_by) REFERENCES users(id)
);
`);

const categories = {
  Roads:'Public Works Department',
  Sanitation:'Sanitation',
  Water:'Water Supply',
  Electricity:'Electricity',
  'Public Safety':'Public Safety',
  Environment:'Environment',
  Other:'General Services'
};

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadDir,
    filename: (req,file,cb)=>{
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, `${Date.now()}-${Math.random().toString(36).slice(2,10)}${ext}`);
    }
  }),
  limits:{fileSize:5*1024*1024},
  fileFilter:(req,file,cb)=>{
    cb(null, /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype));
  }
});

app.use(helmet({contentSecurityPolicy:false}));
app.use(cors());
app.use(express.json({limit:'1mb'}));
app.use(express.urlencoded({extended:true}));
app.use('/uploads', express.static(uploadDir));

function publicUser(row){
  return {id:row.id,name:row.name,email:row.email,phone:row.phone,role:row.role};
}
function signToken(user){
  return jwt.sign({id:user.id, role:user.role}, JWT_SECRET, {expiresIn:'7d'});
}
function auth(required=true){
  return (req,res,next)=>{
    const header=req.headers.authorization||'';
    const token=header.startsWith('Bearer ')?header.slice(7):null;
    if(!token){
      if(required) return res.status(401).json({error:'Authentication required'});
      req.user=null; return next();
    }
    try{
      const payload=jwt.verify(token,JWT_SECRET);
      const user=db.prepare('SELECT * FROM users WHERE id=?').get(payload.id);
      if(!user) return res.status(401).json({error:'Invalid session'});
      req.user=user; next();
    }catch(e){ return res.status(401).json({error:'Invalid or expired token'}); }
  };
}
function admin(req,res,next){
  if(req.user.role!=='admin') return res.status(403).json({error:'Admin access required'});
  next();
}
function makeId(){
  let id;
  do { id='#'+Math.floor(1000+Math.random()*9000); }
  while(db.prepare('SELECT 1 FROM reports WHERE id=?').get(id));
  return id;
}
function reportView(r){
  return {
    id:r.id, category:r.category, description:r.description, location:r.location,
    lat:r.lat, lng:r.lng, ward:'Unassigned', status:r.status, votes:r.votes,
    image:r.image || '', date:new Date(r.created_at+'Z').toLocaleString('en-IN',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'}),
    user:r.user_name, department:r.department, createdAt:r.created_at, updatedAt:r.updated_at
  };
}
const reportSQL = `
SELECT r.*, u.name AS user_name
FROM reports r JOIN users u ON u.id=r.user_id
`;

app.get('/api/health',(req,res)=>res.json({ok:true,service:'CleanCity API'}));

app.post('/api/auth/register', async (req,res)=>{
  try{
    const {name,email,phone,password}=req.body||{};
    if(!name || name.trim().length<2) return res.status(400).json({error:'Please enter your full name.'});
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email||''))) return res.status(400).json({error:'Please enter a valid email address.'});
    if(!/^\d{10}$/.test(String(phone||''))) return res.status(400).json({error:'Please enter a valid 10-digit phone number.'});
    if(String(password||'').length<6) return res.status(400).json({error:'Password must contain at least 6 characters.'});
    const exists=db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase());
    if(exists) return res.status(409).json({error:'An account with this email already exists. Please login.'});
    const hash=await bcrypt.hash(password,12);
    const info=db.prepare('INSERT INTO users(name,email,phone,password_hash) VALUES(?,?,?,?)')
      .run(name.trim(),email.toLowerCase(),phone,hash);
    const user=db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
    res.status(201).json({token:signToken(user),user:publicUser(user)});
  }catch(e){console.error(e);res.status(500).json({error:'Registration failed'});}
});

app.post('/api/auth/login', async (req,res)=>{
  try{
    const {email,password}=req.body||{};
    const user=db.prepare('SELECT * FROM users WHERE email=?').get(String(email||'').toLowerCase());
    if(!user || !(await bcrypt.compare(String(password||''),user.password_hash)))
      return res.status(401).json({error:'Incorrect email or password.'});
    res.json({token:signToken(user),user:publicUser(user)});
  }catch(e){console.error(e);res.status(500).json({error:'Login failed'});}
});

app.get('/api/auth/me',auth(),(req,res)=>res.json({user:publicUser(req.user)}));
app.post('/api/auth/logout',auth(false),(req,res)=>res.json({ok:true}));

app.patch('/api/auth/profile',auth(),(req,res)=>{
  const {name,phone}=req.body||{};
  if(!name || name.trim().length<2) return res.status(400).json({error:'Please enter a valid name'});
  if(!/^\d{10}$/.test(String(phone||''))) return res.status(400).json({error:'Please enter a valid 10-digit phone number'});
  db.prepare('UPDATE users SET name=?,phone=? WHERE id=?').run(name.trim(),phone,req.user.id);
  res.json({user:publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id))});
});

app.get('/api/reports',auth(),(req,res)=>{
  const rows=db.prepare(reportSQL+' ORDER BY r.created_at DESC').all();
  res.json({reports:rows.map(reportView)});
});

app.get('/api/reports/:id',auth(),(req,res)=>{
  const row=db.prepare(reportSQL+' WHERE r.id=?').get(req.params.id);
  if(!row) return res.status(404).json({error:'Report not found'});
  res.json({report:reportView(row)});
});

app.post('/api/reports',auth(),upload.single('photo'),(req,res)=>{
  const {category,description,location,lat,lng}=req.body||{};
  if(!categories[category]) return res.status(400).json({error:'Invalid issue category'});
  if(!description || !location) return res.status(400).json({error:'Description and location are required'});
  const id=makeId();
  const image=req.file ? `/uploads/${req.file.filename}` : '';
  const now=new Date().toISOString().slice(0,19).replace('T',' ');
  const tx=db.transaction(()=>{
    db.prepare(`INSERT INTO reports(id,user_id,category,description,location,lat,lng,status,votes,image,department,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,'Open',0,?,?,?,?)`)
      .run(id,req.user.id,category,description.trim(),location.trim(),
           lat!==undefined ? Number(lat):null,lng!==undefined ? Number(lng):null,
           image,categories[category],now,now);
    db.prepare('INSERT INTO report_status_history(report_id,status,changed_by) VALUES(?,?,?)').run(id,'Open',req.user.id);
  });
  tx();
  const row=db.prepare(reportSQL+' WHERE r.id=?').get(id);
  res.status(201).json({report:reportView(row)});
});

app.post('/api/reports/:id/upvote',auth(),(req,res)=>{
  const r=db.prepare('SELECT id FROM reports WHERE id=?').get(req.params.id);
  if(!r) return res.status(404).json({error:'Report not found'});
  db.prepare('UPDATE reports SET votes=votes+1,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(req.params.id);
  const row=db.prepare('SELECT votes FROM reports WHERE id=?').get(req.params.id);
  res.json({votes:row.votes});
});

app.patch('/api/reports/:id/status',auth(),(req,res)=>{
  if(req.user.role!=='admin') return res.status(403).json({error:'Only an admin can change issue status'});
  const allowed=['Open','In Progress','Resolved'];
  const {status}=req.body||{};
  if(!allowed.includes(status)) return res.status(400).json({error:'Invalid status'});
  const r=db.prepare('SELECT id FROM reports WHERE id=?').get(req.params.id);
  if(!r) return res.status(404).json({error:'Report not found'});
  const tx=db.transaction(()=>{
    db.prepare('UPDATE reports SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status,req.params.id);
    db.prepare('INSERT INTO report_status_history(report_id,status,changed_by) VALUES(?,?,?)').run(req.params.id,status,req.user.id);
  });
  tx();
  const row=db.prepare(reportSQL+' WHERE r.id=?').get(req.params.id);
  res.json({report:reportView(row)});
});

app.get('/api/admin/stats',auth(),admin,(req,res)=>{
  const total=db.prepare('SELECT COUNT(*) n FROM reports').get().n;
  const open=db.prepare("SELECT COUNT(*) n FROM reports WHERE status='Open'").get().n;
  const progress=db.prepare("SELECT COUNT(*) n FROM reports WHERE status='In Progress'").get().n;
  const resolved=db.prepare("SELECT COUNT(*) n FROM reports WHERE status='Resolved'").get().n;
  res.json({total,open,progress,resolved});
});

app.use(express.static(path.join(__dirname,'public')));
app.use((req,res,next)=>{
  if(req.method==='GET') return res.sendFile(path.join(__dirname,'public','index.html'));
  next();
});

app.use((err,req,res,next)=>{
  console.error(err);
  res.status(500).json({error:err.message||'Server error'});
});

app.listen(PORT,()=>console.log(`CleanCity backend running at http://localhost:${PORT}`));