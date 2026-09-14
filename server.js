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
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "Demonexes95@gmail.com").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Wood 2009@zhuo";
const FRONTEND_URL = process.env.FRONTEND_URL || "*";

const DATA_DIR = path.join(__dirname, "data");
const UPLOAD_DIR = path.join(__dirname, "uploads");
fs.mkdirSync(DATA_DIR, {recursive:true});
fs.mkdirSync(UPLOAD_DIR, {recursive:true});

app.use(cors({
  origin: FRONTEND_URL === "*" ? true : FRONTEND_URL.split(",").map(x => x.trim()),
  credentials: true
}));
app.use(express.json({limit:"10mb"}));
app.use(express.urlencoded({extended:true, limit:"10mb"}));
app.use("/uploads", express.static(UPLOAD_DIR));

const dbFile = path.join(DATA_DIR, "db.json");
function defaultDB(){
  return {
    users:[], products:[], promotions:[], orders:[], paymentMethods:[],
    notifications:[], messages:[], streamingPlans:[], streamingOrders:[],
    conversations:[]
  };
}
function readDB(){
  try {
    const d = JSON.parse(fs.readFileSync(dbFile,"utf8"));
    const base = defaultDB();
    for (const k of Object.keys(base)) if (!Array.isArray(d[k])) d[k] = base[k];
    return d;
  } catch {
    const d = defaultDB();
    fs.writeFileSync(dbFile, JSON.stringify(d,null,2));
    return d;
  }
}
function writeDB(d){ fs.writeFileSync(dbFile, JSON.stringify(d,null,2)); }
let db = readDB();

function id(){ return crypto.randomUUID(); }
function now(){ return new Date().toISOString(); }
function safeUser(u){
  if(!u) return null;
  const {passwordHash, ...x} = u;
  return x;
}
function bearer(req){
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}
function auth(req,res,next){
  const token = bearer(req);
  if(!token) return res.status(401).json({message:"Authentification requise"});
  try{
    const p = jwt.verify(token, JWT_SECRET);
    const u = db.users.find(x => x.id === p.id);
    if(!u) return res.status(401).json({message:"Session invalide"});
    req.user = u;
    next();
  }catch(e){
    return res.status(401).json({message:"Session expirée ou invalide"});
  }
}
function admin(req,res,next){
  if(req.user?.role !== "admin") return res.status(403).json({message:"Administrateur requis"});
  next();
}
function tokenFor(u){
  return jwt.sign({id:u.id,email:u.email,role:u.role},JWT_SECRET,{expiresIn:"30d"});
}
function unwrapCustomerId(req, body){
  return body.customer_id || body.customerId || req.user.id;
}

if(!db.users.some(u => u.email === ADMIN_EMAIL)){
  db.users.push({
    id:id(), name:"Administrateur", email:ADMIN_EMAIL,
    passwordHash:bcrypt.hashSync(ADMIN_PASSWORD,10),
    role:"admin", isPrimaryAdmin:true, createdAt:now()
  });
  writeDB(db);
}

/* ---------------- IMAGE UPLOAD ---------------- */
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

app.get("/",(req,res)=>res.json({ok:true,name:"ZhuoMarket Backend",upload:"ready"}));
app.get("/health",(req,res)=>res.json({ok:true,time:now()}));

app.post("/api/uploads", auth, (req,res)=>{
  upload.any()(req,res,(err)=>{
    if(err) return res.status(400).json({message:err.message});
    const f=(req.files||[])[0];
    if(!f) return res.status(400).json({message:"Aucune image reçue. Utilisez image, file ou photo."});
    const url=`${req.protocol}://${req.get("host")}/uploads/${f.filename}`;
    res.status(201).json({ok:true,url,image:url,imageUrl:url,fileUrl:url,path:url});
  });
});

/* ---------------- AUTH ---------------- */
app.post("/api/auth/register", async(req,res)=>{
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
  if(!u || !(await bcrypt.compare(password,u.passwordHash)))
    return res.status(401).json({message:"Email ou mot de passe incorrect"});
  res.json({user:safeUser(u),token:tokenFor(u)});
});
app.get("/api/auth/me",auth,(req,res)=>res.json({user:safeUser(req.user)}));
function updateMe(req,res){
  const u=req.user;
  for(const k of ["name","avatar","photoUrl","photo","image"])
    if(req.body[k]!==undefined) u[k]=String(req.body[k]);
  writeDB(db);
  res.json({user:safeUser(u)});
}
app.patch("/api/auth/me",auth,updateMe);
app.put("/api/auth/me",auth,updateMe);
app.post("/api/auth/logout",(req,res)=>res.json({ok:true}));
app.post("/api/auth/refresh",auth,(req,res)=>res.json({token:tokenFor(req.user),user:safeUser(req.user)}));

/* ---------------- PRODUCTS ---------------- */
app.get("/api/products",(req,res)=>res.json(db.products.filter(p=>p.status!=="deleted")));
app.get("/api/brands",(req,res)=>{
  const brands=[...new Set(db.products.map(p=>p.brand).filter(Boolean))];
  res.json(brands.map((name,i)=>({id:String(i+1),name})));
});
app.post("/api/products",auth,admin,(req,res)=>{
  const b=req.body||{};
  const p={
    id:id(), brand:String(b.brand||""), model:String(b.model||b.name||b.title||""),
    name:String(b.name||b.model||""), title:String(b.title||b.model||""),
    image:String(b.image||b.imageUrl||""), imageUrl:String(b.imageUrl||b.image||""),
    images:Array.isArray(b.images)?b.images.filter(Boolean):[],
    price:Number(b.price||0), oldPrice:Number(b.oldPrice||0), discount:Number(b.discount||0),
    stock:Number(b.stock??b.quantity??0), quantity:Number(b.quantity??b.stock??0),
    storage:b.storage||[], colors:b.colors||[], specifications:b.specifications||{},
    description:String(b.description||""), status:b.status||"published",
    published:b.published!==false, createdAt:now(), updatedAt:now()
  };
  db.products.push(p); writeDB(db); res.status(201).json(p);
});
function productUpdate(req,res){
  const p=db.products.find(x=>x.id===req.params.id);
  if(!p)return res.status(404).json({message:"Produit introuvable"});
  Object.assign(p,req.body,{updatedAt:now()});
  if(req.body.quantity!==undefined && req.body.stock===undefined)p.stock=Number(req.body.quantity);
  if(req.body.stock!==undefined && req.body.quantity===undefined)p.quantity=Number(req.body.stock);
  writeDB(db); res.json(p);
}
app.put("/api/products/:id",auth,admin,productUpdate);
app.patch("/api/products/:id",auth,admin,productUpdate);
app.delete("/api/products/:id",auth,admin,(req,res)=>{
  const i=db.products.findIndex(x=>x.id===req.params.id);
  if(i<0)return res.status(404).json({message:"Produit introuvable"});
  db.products.splice(i,1); writeDB(db); res.json({ok:true});
});

/* ---------------- PROMOTIONS ---------------- */
app.get("/api/promotions",(req,res)=>res.json(db.promotions.filter(p=>p.status!=="deleted")));
function savePromotion(req,res,pid){
  let p=pid?db.promotions.find(x=>x.id===pid):null;
  if(pid&&!p)return res.status(404).json({message:"Publicité introuvable"});
  if(!p){p={id:id(),createdAt:now()};db.promotions.push(p);}
  Object.assign(p,req.body,{updatedAt:now()});
  if(!Array.isArray(p.images))p.images=p.image?[p.image]:[];
  writeDB(db); res.status(pid?200:201).json(p);
}
app.post("/api/promotions",auth,admin,(req,res)=>savePromotion(req,res));
app.put("/api/promotions/:id",auth,admin,(req,res)=>savePromotion(req,res,req.params.id));
app.patch("/api/promotions/:id",auth,admin,(req,res)=>savePromotion(req,res,req.params.id));
app.delete("/api/promotions/:id",auth,admin,(req,res)=>{
  const i=db.promotions.findIndex(x=>x.id===req.params.id);
  if(i<0)return res.status(404).json({message:"Publicité introuvable"});
  db.promotions.splice(i,1);writeDB(db);res.json({ok:true});
});
// Compatibility alias used by some frontend builds.
app.get("/api/admin/promotions/:id",auth,admin,(req,res)=>{
  const p=db.promotions.find(x=>x.id===req.params.id);
  if(!p)return res.status(404).json({message:"Publicité introuvable"});
  res.json(p);
});

/* ---------------- USERS / ADMIN ---------------- */
function updateUser(req,res){
  const u=db.users.find(x=>x.id===req.params.id);
  if(!u)return res.status(404).json({message:"Utilisateur introuvable"});
  if(u.isPrimaryAdmin && req.body.role && req.body.role!=="admin")
    return res.status(403).json({message:"Le compte administrateur principal est protégé"});
  if(req.body.role)u.role=req.body.role;
  if(req.body.name!==undefined)u.name=String(req.body.name);
  writeDB(db);res.json({user:safeUser(u)});
}
app.get("/api/users",auth,admin,(req,res)=>res.json(db.users.map(safeUser)));
app.patch("/api/users/:id",auth,admin,updateUser);
app.patch("/api/admin/users/:id",auth,admin,updateUser);
app.get("/api/admin/users",auth,admin,(req,res)=>res.json(db.users.map(safeUser)));

app.get("/api/admin/stats",auth,admin,(req,res)=>{
  const totalSales=db.orders.reduce((s,o)=>s+Number(o.total||o.amount||0),0);
  const daily={};
  for(const o of db.orders){
    const d=String(o.createdAt||"").slice(0,10)||"unknown";
    daily[d]=(daily[d]||0)+Number(o.total||o.amount||0);
  }
  const dailySales=Object.entries(daily).sort().map(([date,value])=>({date,label:date,value}));
  res.json({
    users:db.users.length,products:db.products.length,promotions:db.promotions.length,
    orders:db.orders.length,pendingPayments:db.orders.filter(o=>o.paymentStatus==="pending").length,
    totalSales,revenue:totalSales,ordersCount:db.orders.length,dailySales
  });
});

/* ---------------- ORDERS / PAYMENTS ---------------- */
app.get("/api/orders",auth,(req,res)=>{
  res.json(db.orders.filter(o=>o.customer_id===req.user.id||o.customerId===req.user.id||req.user.role==="admin"));
});
app.get("/api/admin/orders",auth,admin,(req,res)=>res.json(db.orders));
app.post("/api/orders",auth,(req,res)=>{
  const o={
    id:id(),...req.body,customer_id:req.user.id,customerId:req.user.id,
    status:req.body.status||"pending",paymentStatus:req.body.paymentStatus||"pending",createdAt:now()
  };
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
  if(req.user.role!=="admin" && o.customer_id!==req.user.id)return res.status(403).json({message:"Accès refusé"});
  Object.assign(o,{
    paymentStatus:"pending",
    transaction_reference:req.body.transaction_reference||req.body.transactionReference||"",
    paymentMethod:req.body.paymentMethod||"",
    updatedAt:now()
  });
  writeDB(db);res.json(o);
});
app.post("/api/admin/orders/:id/confirmation-code",auth,admin,(req,res)=>{
  const o=db.orders.find(x=>x.id===req.params.id);
  if(!o)return res.status(404).json({message:"Commande introuvable"});
  const code=String(req.body.code||req.body.confirmationCode||"").trim();
  o.confirmationCode=code;o.paymentStatus="verified";o.status=req.body.status||"confirmed";o.updatedAt=now();
  writeDB(db);res.json(o);
});

/* ---------------- PAYMENT METHODS ---------------- */
function normalizePayment(p){
  const x={...p};
  if(x.enabled===undefined)x.enabled=x.active!==false;
  if(x.active===undefined)x.active=x.enabled!==false;
  return x;
}
app.get("/api/payment-methods",(req,res)=>res.json(db.paymentMethods.filter(x=>x.active!==false && x.enabled!==false).map(normalizePayment)));
app.get("/api/admin/payment-methods",auth,admin,(req,res)=>res.json(db.paymentMethods.map(normalizePayment)));
app.post("/api/admin/payment-methods",auth,admin,(req,res)=>{
  const p=normalizePayment({id:id(),...req.body,createdAt:now()});
  db.paymentMethods.push(p);writeDB(db);res.status(201).json(p);
});
function updatePayment(req,res){
  const p=db.paymentMethods.find(x=>x.id===req.params.id);
  if(!p)return res.status(404).json({message:"Méthode introuvable"});
  Object.assign(p,req.body);
  if(req.body.enabled!==undefined)p.active=!!req.body.enabled;
  if(req.body.active!==undefined)p.enabled=!!req.body.active;
  writeDB(db);res.json(normalizePayment(p));
}
app.put("/api/admin/payment-methods/:id",auth,admin,updatePayment);
app.patch("/api/admin/payment-methods/:id",auth,admin,updatePayment);
app.delete("/api/admin/payment-methods/:id",auth,admin,(req,res)=>{
  db.paymentMethods=db.paymentMethods.filter(x=>x.id!==req.params.id);writeDB(db);res.json({ok:true});
});

/* ---------------- STREAMING ---------------- */
app.get("/api/streaming-plans",(req,res)=>res.json(db.streamingPlans));
app.get("/api/admin/streaming-plans",auth,admin,(req,res)=>res.json(db.streamingPlans));
app.get("/api/admin/streaming-orders",auth,admin,(req,res)=>res.json(db.streamingOrders));
app.post("/api/streaming-orders",auth,(req,res)=>{
  const x={id:id(),...req.body,customer_id:req.user.id,customerId:req.user.id,createdAt:now(),
    paymentStatus:req.body.paymentStatus||"pending",status:req.body.status||"Nouvelle demande"};
  db.streamingOrders.push(x);writeDB(db);res.status(201).json(x);
});
app.post("/api/admin/streaming-plans",auth,admin,(req,res)=>{
  // Accept either {plans:[...]} or one plan object.
  if(Array.isArray(req.body?.plans)){
    db.streamingPlans=req.body.plans.map(x=>({...x,id:x.id||id()}));
  }else{
    db.streamingPlans.push({id:id(),...req.body});
  }
  writeDB(db);res.status(201).json(db.streamingPlans);
});
app.put("/api/admin/streaming-plans",auth,admin,(req,res)=>{
  if(!Array.isArray(req.body?.plans)) return res.status(400).json({message:"plans doit être un tableau"});
  db.streamingPlans=req.body.plans.map(x=>({...x,id:x.id||id()}));
  writeDB(db);res.json(db.streamingPlans);
});

/* ---------------- NOTIFICATIONS ---------------- */
app.get("/api/notifications",auth,(req,res)=>{
  const list=db.notifications.filter(x=>x.userId===req.user.id||x.user_id===req.user.id);
  res.json({notifications:list,unread:list.filter(x=>!x.read&&!x.seenAt).length});
});
app.get("/api/admin/notifications",auth,admin,(req,res)=>res.json({notifications:db.notifications}));
app.patch("/api/notifications/:id/read",auth,(req,res)=>{
  const n=db.notifications.find(x=>x.id===req.params.id && (x.userId===req.user.id||x.user_id===req.user.id));
  if(!n)return res.status(404).json({message:"Notification introuvable"});
  n.read=true;n.seenAt=now();writeDB(db);res.json(n);
});
app.post("/api/notifications/mark-all-read",auth,(req,res)=>{
  for(const n of db.notifications) if(n.userId===req.user.id||n.user_id===req.user.id){n.read=true;n.seenAt=now();}
  writeDB(db);res.json({ok:true});
});
app.get("/api/notifications/due-reminders",auth,(req,res)=>res.json({reminders:[]}));

/* ---------------- CUSTOMER / ADMIN MESSAGES ---------------- */
function conversationFor(userId){
  let c=db.conversations.find(x=>x.userId===userId);
  if(!c){ c={id:id(),userId,createdAt:now()};db.conversations.push(c); }
  return c;
}
function addMessage(userId, text, extra={}){
  const c=conversationFor(userId);
  const m={id:id(),conversationId:c.id,userId,from:extra.from||"client",text:String(text||""),message:String(text||""),createdAt:now(),
    read:false, ...extra};
  db.messages.push(m);writeDB(db);return m;
}
app.get("/api/messages",auth,(req,res)=>{
  const c=conversationFor(req.user.id);
  const messages=db.messages.filter(x=>x.conversationId===c.id||x.userId===req.user.id);
  writeDB(db);res.json({conversationId:c.id,messages});
});
app.post("/api/messages",auth,(req,res)=>{
  const m=addMessage(req.user.id,req.body.message||req.body.text,{from:"client",urgent:!!req.body.urgent,severity:req.body.severity||"normal",source:req.body.source});
  res.status(201).json({message:m,conversationId:m.conversationId});
});
app.get("/api/admin/messages",auth,admin,(req,res)=>{
  const grouped=new Map();
  for(const m of db.messages){
    const key=String(m.userId||"unknown");
    if(!grouped.has(key)) grouped.set(key,[]);
    grouped.get(key).push(m);
  }
  const conversations=[...grouped.entries()].map(([userId,msgs])=>{
    const u=db.users.find(x=>x.id===userId);
    const last=msgs[msgs.length-1];
    return {id:conversationFor(userId).id,userId,name:u?.name||"Client",email:u?.email||"",avatar:u?.avatar||u?.photoUrl||"",
      lastMessage:last?.text||last?.message||"",lastMessageAt:last?.createdAt||null,unread:msgs.filter(x=>!x.read&&x.from!=="admin").length};
  });
  res.json({conversations,messages:db.messages});
});
app.get("/api/admin/messages/unread",auth,admin,(req,res)=>res.json({messages:db.messages.filter(x=>!x.read&&x.from!=="admin")}));
app.get("/api/admin/messages/:id",auth,admin,(req,res)=>{
  const c=db.conversations.find(x=>x.id===req.params.id);
  if(!c)return res.status(404).json({message:"Conversation introuvable"});
  res.json({messages:db.messages.filter(x=>x.conversationId===c.id)});
});
app.post("/api/admin/messages/:id",auth,admin,(req,res)=>{
  const c=db.conversations.find(x=>x.id===req.params.id);
  if(!c)return res.status(404).json({message:"Conversation introuvable"});
  const m=addMessage(c.userId,req.body.message||req.body.text,{from:"admin",adminId:req.user.id});
  res.status(201).json(m);
});
app.post("/api/admin/messages",auth,admin,(req,res)=>{
  const userId=req.body.userId||req.body.customerId;
  if(!userId)return res.status(400).json({message:"userId requis"});
  const m=addMessage(userId,req.body.message||req.body.text,{from:"admin",adminId:req.user.id});
  res.status(201).json(m);
});

/* ---------------- CHATBOT ---------------- */
app.post("/api/chatbot",auth,(req,res)=>{
  res.json({
    reply:"Votre message a bien été reçu. Un administrateur pourra vous répondre.",
    needsAdmin:true,
    conversationId:conversationFor(req.user.id).id,
    severity:req.body?.severity||"normal"
  });
});

/* ---------------- PAYPAL ----------------
   No fake payment is performed. These routes return a clear configuration
   error until real PayPal credentials are supplied to the backend.
*/
app.post("/api/payments/paypal/create-order",auth,(req,res)=>{
  if(!process.env.PAYPAL_CLIENT_ID || !process.env.PAYPAL_CLIENT_SECRET)
    return res.status(503).json({message:"PayPal n'est pas configuré sur le backend. Ajoutez PAYPAL_CLIENT_ID et PAYPAL_CLIENT_SECRET."});
  return res.status(501).json({message:"Le connecteur PayPal réel doit être configuré côté backend."});
});
app.post("/api/payments/paypal/capture",auth,(req,res)=>{
  if(!process.env.PAYPAL_CLIENT_ID || !process.env.PAYPAL_CLIENT_SECRET)
    return res.status(503).json({message:"PayPal n'est pas configuré sur le backend."});
  return res.status(501).json({message:"Le connecteur PayPal réel doit être configuré côté backend."});
});

/* ---------------- ERRORS ---------------- */
app.use((err,req,res,next)=>{
  console.error(err);
  if(err instanceof multer.MulterError)
    return res.status(400).json({message:"Upload refusé: "+err.message});
  res.status(500).json({
    message:"Erreur interne du serveur",
    error:process.env.NODE_ENV==="production"?"Erreur serveur":err.message
  });
});

app.listen(PORT,()=>console.log(`ZhuoMarket backend listening on ${PORT}`));
