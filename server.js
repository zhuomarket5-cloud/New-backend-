
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.set("trust proxy", 1);

const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_ZHUOMARKET_SECRET";
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "admin@zhuomarket.com").toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ChangeMe123!";
const FRONTEND_URL = process.env.FRONTEND_URL || "*";

const DATA_DIR = path.join(__dirname, "data");
const UPLOAD_DIR = path.join(__dirname, "uploads");
fs.mkdirSync(DATA_DIR, {recursive:true});
fs.mkdirSync(UPLOAD_DIR, {recursive:true});

app.use(cors({
  origin: FRONTEND_URL === "*" ? true : FRONTEND_URL.split(",").map(x=>x.trim()),
  credentials:true
}));
app.use(express.json({limit:"10mb"}));
app.use(express.urlencoded({extended:true, limit:"10mb"}));
app.use("/uploads", express.static(UPLOAD_DIR));

const dbFile = path.join(DATA_DIR, "db.json");
function readDB(){
  try { return JSON.parse(fs.readFileSync(dbFile,"utf8")); }
  catch {
    const d={users:[],products:[],promotions:[],orders:[],paymentMethods:[],notifications:[],messages:[],streamingPlans:[],streamingOrders:[]};
    fs.writeFileSync(dbFile, JSON.stringify(d,null,2));
    return d;
  }
}
function writeDB(d){ fs.writeFileSync(dbFile, JSON.stringify(d,null,2)); }
let db = readDB();

function id(){ return crypto.randomUUID(); }
function now(){ return new Date().toISOString(); }
function safeUser(u){ if(!u)return null; const {passwordHash,...x}=u; return x; }

if(!db.users.some(u=>u.email===ADMIN_EMAIL)){
  db.users.push({
    id:id(), name:"Administrateur", email:ADMIN_EMAIL,
    passwordHash:bcrypt.hashSync(ADMIN_PASSWORD,10),
    role:"admin", isPrimaryAdmin:true, createdAt:now()
  });
  writeDB(db);
}

function tokenFor(u){ return jwt.sign({id:u.id,email:u.email,role:u.role},JWT_SECRET,{expiresIn:"30d"}); }
function auth(req,res,next){
  const h=req.headers.authorization||"";
  const token=h.startsWith("Bearer ") ? h.slice(7) : null;
  if(!token) return res.status(401).json({message:"Authentification requise"});
  try{
    const p=jwt.verify(token,JWT_SECRET);
    const u=db.users.find(x=>x.id===p.id);
    if(!u) return res.status(401).json({message:"Session invalide"});
    req.user=u; next();
  }catch(e){ return res.status(401).json({message:"Session expirée ou invalide"}); }
}
function admin(req,res,next){
  if(req.user?.role!=="admin") return res.status(403).json({message:"Administrateur requis"});
  next();
}

const storage = multer.diskStorage({
  destination:(req,file,cb)=>cb(null,UPLOAD_DIR),
  filename:(req,file,cb)=>{
    const ext=(path.extname(file.originalname)||".jpg").toLowerCase();
    cb(null, Date.now()+"-"+crypto.randomBytes(6).toString("hex")+ext);
  }
});
const upload = multer({
  storage,
  limits:{fileSize:8*1024*1024, files:10},
  fileFilter:(req,file,cb)=>{
    if(/^image\/(jpeg|png|webp|gif|jpg)$/i.test(file.mimetype)) cb(null,true);
    else cb(new Error("Seules les images JPG, PNG, WEBP ou GIF sont acceptées."));
  }
});

// Health
app.get("/",(req,res)=>res.json({ok:true,name:"ZhuoMarket Backend",upload:"ready"}));
app.get("/health",(req,res)=>res.json({ok:true,time:now()}));

// REAL IMAGE UPLOAD. Accepts all common field names used by the frontend.
app.post("/api/uploads", auth, (req,res)=>{
  upload.any()(req,res,(err)=>{
    if(err) return res.status(400).json({message:err.message});
    const f=(req.files||[])[0];
    if(!f) return res.status(400).json({message:"Aucune image reçue. Utilisez image ou file."});
    const url = `${req.protocol}://${req.get("host")}/uploads/${f.filename}`;
    return res.status(201).json({ok:true,url,image:url,imageUrl:url,fileUrl:url,path:url});
  });
});

// Auth
app.post("/api/auth/register",async(req,res)=>{
  const email=String(req.body.email||"").trim().toLowerCase();
  const password=String(req.body.password||"");
  const name=String(req.body.name||req.body.username||"Utilisateur").trim();
  if(!email||!password) return res.status(400).json({message:"Email et mot de passe requis"});
  if(db.users.some(u=>u.email===email)) return res.status(409).json({message:"Compte déjà existant"});
  const u={id:id(),name,email,passwordHash:await bcrypt.hash(password,10),role:"client",createdAt:now()};
  db.users.push(u); writeDB(db);
  res.status(201).json({user:safeUser(u),token:tokenFor(u)});
});
app.post("/api/auth/login",async(req,res)=>{
  const email=String(req.body.email||"").trim().toLowerCase();
  const password=String(req.body.password||"");
  const u=db.users.find(x=>x.email===email);
  if(!u || !(await bcrypt.compare(password,u.passwordHash))) return res.status(401).json({message:"Email ou mot de passe incorrect"});
  res.json({user:safeUser(u),token:tokenFor(u)});
});
app.get("/api/auth/me",auth,(req,res)=>res.json({user:safeUser(req.user)}));
app.patch("/api/auth/me",auth,(req,res)=>updateMe(req,res));
app.put("/api/auth/me",auth,(req,res)=>updateMe(req,res));
function updateMe(req,res){
  const u=req.user;
  for(const k of ["name","avatar","photoUrl","photo","image"]) if(req.body[k]!==undefined) u[k]=String(req.body[k]);
  writeDB(db); res.json({user:safeUser(u)});
}
app.post("/api/auth/logout",(req,res)=>res.json({ok:true}));
app.post("/api/auth/refresh",auth,(req,res)=>res.json({token:tokenFor(req.user),user:safeUser(req.user)}));

// Public catalogue
app.get("/api/products",(req,res)=>res.json(db.products));
app.get("/api/brands",(req,res)=>{
  const brands=[...new Set(db.products.map(p=>p.brand).filter(Boolean))];
  res.json(brands.map((name,i)=>({id:String(i+1),name})));
});
app.get("/api/promotions",(req,res)=>res.json(db.promotions.filter(p=>p.status!=="deleted")));

// Product admin CRUD
app.post("/api/products",auth,admin,(req,res)=>{
  const b=req.body||{};
  const p={id:id(),brand:String(b.brand||""),model:String(b.model||b.name||b.title||""),
    name:String(b.name||b.model||""),title:String(b.title||b.model||""),
    image:String(b.image||b.imageUrl||""),imageUrl:String(b.imageUrl||b.image||""),
    images:Array.isArray(b.images)?b.images.filter(Boolean):[],
    price:Number(b.price||0),oldPrice:Number(b.oldPrice||0),discount:Number(b.discount||0),
    stock:Number(b.stock??b.quantity??0),quantity:Number(b.quantity??b.stock??0),
    storage:b.storage||[],colors:b.colors||[],specifications:b.specifications||{},
    description:String(b.description||""),status:b.status||"published",published:b.published!==false,createdAt:now(),updatedAt:now()};
  db.products.push(p); writeDB(db); res.status(201).json(p);
});
app.put("/api/products/:id",auth,admin,(req,res)=>productUpdate(req,res));
app.patch("/api/products/:id",auth,admin,(req,res)=>productUpdate(req,res));
function productUpdate(req,res){
  const p=db.products.find(x=>x.id===req.params.id);
  if(!p)return res.status(404).json({message:"Produit introuvable"});
  Object.assign(p,req.body,{updatedAt:now()});
  if(req.body.quantity!==undefined && req.body.stock===undefined)p.stock=Number(req.body.quantity);
  if(req.body.stock!==undefined && req.body.quantity===undefined)p.quantity=Number(req.body.stock);
  writeDB(db);res.json(p);
}
app.delete("/api/products/:id",auth,admin,(req,res)=>{
  const i=db.products.findIndex(x=>x.id===req.params.id);
  if(i<0)return res.status(404).json({message:"Produit introuvable"});
  db.products.splice(i,1);writeDB(db);res.json({ok:true});
});

// Promotions
app.post("/api/promotions",auth,admin,(req,res)=>savePromotion(req,res));
app.put("/api/promotions/:id",auth,admin,(req,res)=>savePromotion(req,res,req.params.id));
app.patch("/api/promotions/:id",auth,admin,(req,res)=>savePromotion(req,res,req.params.id));
function savePromotion(req,res,pid){
  let p=pid?db.promotions.find(x=>x.id===pid):null;
  if(pid&&!p)return res.status(404).json({message:"Publicité introuvable"});
  if(!p){p={id:id(),createdAt:now()};db.promotions.push(p);}
  Object.assign(p,req.body,{updatedAt:now()});
  if(!Array.isArray(p.images))p.images=p.image?[p.image]:[];
  writeDB(db);res.status(pid?200:201).json(p);
}
app.delete("/api/promotions/:id",auth,admin,(req,res)=>{
  const i=db.promotions.findIndex(x=>x.id===req.params.id);
  if(i<0)return res.status(404).json({message:"Publicité introuvable"});
  db.promotions.splice(i,1);writeDB(db);res.json({ok:true});
});

// Users/admin
app.get("/api/users",auth,admin,(req,res)=>res.json(db.users.map(safeUser)));
app.patch("/api/users/:id",auth,admin,(req,res)=>{
  const u=db.users.find(x=>x.id===req.params.id);
  if(!u)return res.status(404).json({message:"Utilisateur introuvable"});
  if(u.isPrimaryAdmin && req.body.role && req.body.role!=="admin") return res.status(403).json({message:"Le compte administrateur principal est protégé"});
  if(req.body.role)u.role=req.body.role;
  if(req.body.name!==undefined)u.name=String(req.body.name);
  writeDB(db);res.json({user:safeUser(u)});
});
app.get("/api/admin/stats",auth,admin,(req,res)=>res.json({
  users:db.users.length,products:db.products.length,promotions:db.promotions.length,
  orders:db.orders.length,pendingPayments:db.orders.filter(o=>o.paymentStatus==="pending").length
}));

// Orders
app.get("/api/orders",auth,(req,res)=>res.json(db.orders.filter(o=>o.customer_id===req.user.id||o.customerId===req.user.id||req.user.role==="admin")));
app.post("/api/orders",auth,(req,res)=>{
  const o={id:id(),...req.body,customer_id:req.user.id,customerId:req.user.id,status:req.body.status||"pending",paymentStatus:req.body.paymentStatus||"pending",createdAt:now()};
  db.orders.push(o);writeDB(db);res.status(201).json(o);
});
app.patch("/api/orders/:id",auth,(req,res)=>{
  const o=db.orders.find(x=>x.id===req.params.id);
  if(!o)return res.status(404).json({message:"Commande introuvable"});
  if(req.user.role!=="admin" && o.customer_id!==req.user.id)return res.status(403).json({message:"Accès refusé"});
  Object.assign(o,req.body,{updatedAt:now()});writeDB(db);res.json(o);
});
app.post("/api/orders/:id/payment-confirmation",auth,(req,res)=>{
  const o=db.orders.find(x=>x.id===req.params.id);
  if(!o)return res.status(404).json({message:"Commande introuvable"});
  Object.assign(o,{paymentStatus:"pending",transaction_reference:req.body.transaction_reference||req.body.transactionReference||"",paymentMethod:req.body.paymentMethod||"",updatedAt:now()});
  writeDB(db);res.json(o);
});

// Payment methods
app.get("/api/payment-methods",(req,res)=>res.json(db.paymentMethods.filter(x=>x.active!==false)));
app.get("/api/admin/payment-methods",auth,admin,(req,res)=>res.json(db.paymentMethods));
app.post("/api/admin/payment-methods",auth,admin,(req,res)=>{
  const p={id:id(),...req.body,active:req.body.active!==false,createdAt:now()};db.paymentMethods.push(p);writeDB(db);res.status(201).json(p);
});
app.put("/api/admin/payment-methods/:id",auth,admin,(req,res)=>{
  const p=db.paymentMethods.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({message:"Méthode introuvable"});
  Object.assign(p,req.body);writeDB(db);res.json(p);
});
app.delete("/api/admin/payment-methods/:id",auth,admin,(req,res)=>{
  db.paymentMethods=db.paymentMethods.filter(x=>x.id!==req.params.id);writeDB(db);res.json({ok:true});
});

// Streaming
app.get("/api/streaming-plans",(req,res)=>res.json(db.streamingPlans));
app.get("/api/admin/streaming-plans",auth,admin,(req,res)=>res.json(db.streamingPlans));
app.get("/api/admin/streaming-orders",auth,admin,(req,res)=>res.json(db.streamingOrders));
app.post("/api/admin/streaming-plans",auth,admin,(req,res)=>{const x={id:id(),...req.body};db.streamingPlans.push(x);writeDB(db);res.status(201).json(x);});

// Notifications/messages/chatbot basic real persistence
app.get("/api/notifications",auth,(req,res)=>res.json(db.notifications.filter(x=>x.userId===req.user.id)));
app.get("/api/admin/notifications",auth,admin,(req,res)=>res.json(db.notifications));
app.get("/api/admin/messages",auth,admin,(req,res)=>res.json(db.messages));
app.get("/api/admin/messages/unread",auth,admin,(req,res)=>res.json(db.messages.filter(x=>!x.read)));
app.post("/api/admin/messages",auth,(req,res)=>{const x={id:id(),...req.body,createdAt:now(),read:false,userId:req.user.id};db.messages.push(x);writeDB(db);res.status(201).json(x);});
app.post("/api/chatbot",auth,(req,res)=>res.json({reply:"Votre message a bien été reçu. Un administrateur pourra vous répondre.",needsAdmin:true}));

app.use((err,req,res,next)=>{
  console.error(err);
  if(err instanceof multer.MulterError) return res.status(400).json({message:"Upload refusé: "+err.message});
  res.status(500).json({message:"Erreur interne du serveur",error:process.env.NODE_ENV==="production"?"Erreur serveur":err.message});
});

app.listen(PORT,()=>console.log(`ZhuoMarket backend listening on ${PORT}`));
