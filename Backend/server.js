require('dotenv').config();
const express    = require('express');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const http       = require('http');
const crypto     = require('crypto');
const https      = require('https');
const { Server } = require('socket.io');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

app.use(cors({ origin: '*' }));
app.use(express.json());

// ── MongoDB ─────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('[OK] MongoDB connected'))
  .catch(err => console.error('[ERR] MongoDB:', err.message));

// ── Schemas ─────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  name:          { type: String, required: true, trim: true },
  email:         { type: String, required: true, unique: true, lowercase: true },
  password:      { type: String, required: true },
  isPremium:     { type: Boolean, default: false },
  premiumExpiry: { type: Date, default: null },
  createdAt:     { type: Date, default: Date.now }
});

const orderSchema = new mongoose.Schema({
  billRef:   { type: String, required: true, unique: true },
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount:    { type: Number, default: 5.00 },
  qrString:  { type: String },
  md5Hash:   { type: String },
  status:    { type: String, enum: ['pending','completed','expired'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const User  = mongoose.model('User',  userSchema);
const Order = mongoose.model('Order', orderSchema);

// ── WebSocket ───────────────────────────────────────────
const connectedUsers = new Map();

io.on('connection', function(socket) {
  socket.on('register', function(userId) {
    connectedUsers.set(userId.toString(), socket.id);
    console.log('[WS] User connected: ' + userId);
  });
  socket.on('disconnect', function() {
    for (var entry of connectedUsers.entries()) {
      if (entry[1] === socket.id) {
        connectedUsers.delete(entry[0]);
        break;
      }
    }
  });
});

function notifyUser(userId, event, data) {
  var sid = connectedUsers.get(userId.toString());
  if (sid) io.to(sid).emit(event, data);
}

// ── Auth Middleware ─────────────────────────────────────
function authenticate(req, res, next) {
  var token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch(e) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── HTTP helper (replaces fetch) ────────────────────────
function httpPost(hostname, path, headers, body) {
  return new Promise(function(resolve, reject) {
    var data = JSON.stringify(body);
    var options = {
      hostname: hostname,
      port: 443,
      path: path,
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }, headers)
    };
    var req = https.request(options, function(res) {
      var chunks = [];
      res.on('data', function(c) { chunks.push(c); });
      res.on('end', function() {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
        catch(e) { resolve({}); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// ── CRC16 for KHQR ──────────────────────────────────────
function crc16(str) {
  var crc = 0xFFFF;
  for (var i = 0; i < str.length; i++) {
    crc ^= str.charCodeAt(i) << 8;
    for (var j = 0; j < 8; j++) {
      crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1);
    }
  }
  return (crc & 0xFFFF).toString(16).toUpperCase().padStart(4, '0');
}

// ── Generate KHQR ──────────────────────────────────────
function generateKHQR(merchantId, merchantName, amount, billRef) {
  function enc(id, val) {
    var v = String(val);
    return id + String(v.length).padStart(2, '0') + v;
  }
  var acctInfo = enc('00', 'A000000440') + enc('01', merchantId) + enc('02', billRef);
  var tag29    = enc('29', acctInfo);
  var tag62    = enc('62', enc('05', billRef));
  var name     = merchantName.substring(0, 25);
  var body =
    enc('00', '01') +
    enc('01', '12') +
    tag29 +
    enc('52', '5999') +
    enc('53', '840') +
    enc('54', amount.toFixed(2)) +
    enc('58', 'KH') +
    enc('59', name) +
    enc('60', 'PHNOM PENH') +
    tag62 +
    '6304';
  return body + crc16(body);
}

// ── Bakong API ──────────────────────────────────────────
function checkBakong(md5Hash) {
  if (!process.env.BAKONG_TOKEN) return Promise.resolve(null);
  return httpPost(
    'api-bakong.nbc.org.kh',
    '/v1/check_transaction_by_md5',
    { 'Authorization': 'Bearer ' + process.env.BAKONG_TOKEN },
    { md5: md5Hash }
  ).catch(function(e) {
    console.error('[ERR] Bakong:', e.message);
    return null;
  });
}

// ── Telegram ────────────────────────────────────────────
function sendTelegram(text) {
  if (!process.env.BOT_TOKEN || !process.env.ADMIN_CHAT_ID) return Promise.resolve();
  return httpPost(
    'api.telegram.org',
    '/bot' + process.env.BOT_TOKEN + '/sendMessage',
    {},
    { chat_id: process.env.ADMIN_CHAT_ID, text: text, parse_mode: 'Markdown' }
  ).catch(function(e) { console.error('[ERR] Telegram:', e.message); });
}

// ── Activate Premium ────────────────────────────────────
async function activatePremium(order) {
  var fresh = await Order.findById(order._id);
  if (!fresh || fresh.status === 'completed') return;

  var expiry = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
  await User.findByIdAndUpdate(order.userId, { isPremium: true, premiumExpiry: expiry });
  await Order.findByIdAndUpdate(order._id, { status: 'completed' });

  notifyUser(order.userId, 'payment_confirmed', {
    message: 'Payment confirmed! Quiz Unlocked!',
    billRef: order.billRef
  });

  var user = await User.findById(order.userId);
  await sendTelegram(
    '[OK] Payment Confirmed!\n' +
    'User: ' + (user ? user.name : '') + ' (' + (user ? user.email : '') + ')\n' +
    'Amount: $' + order.amount + '\n' +
    'Ref: ' + order.billRef + '\n' +
    'Premium Activated!'
  );
  console.log('[OK] Premium activated: ' + order.userId);
}

// ── Bakong Polling ──────────────────────────────────────
function startBakongPolling(orderId, md5Hash, billRef) {
  var attempts = 0;
  var MAX = 120;
  var timer = setInterval(async function() {
    attempts++;
    if (attempts > MAX) {
      clearInterval(timer);
      await Order.findByIdAndUpdate(orderId, { status: 'expired' });
      console.log('[TIMEOUT] Order expired: ' + billRef);
      return;
    }
    var order = await Order.findById(orderId);
    if (!order || order.status !== 'pending') { clearInterval(timer); return; }

    var result = await checkBakong(md5Hash);
    if (result && result.responseCode === 0 && result.data) {
      clearInterval(timer);
      console.log('[OK] Bakong confirmed: ' + billRef);
      await activatePremium(order);
    }
  }, 5000);
}

// ══════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════

app.get('/', function(req, res) {
  res.json({ status: 'MD Quiz API running', time: new Date().toISOString() });
});

// REGISTER
app.post('/api/register', async function(req, res) {
  try {
    var name = req.body.name, email = req.body.email, password = req.body.password;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password min 6 characters' });
    if (await User.findOne({ email: email.toLowerCase() }))
      return res.status(400).json({ error: 'Email already registered' });
    var hashed = await bcrypt.hash(password, 12);
    var user   = await User.create({ name, email: email.toLowerCase(), password: hashed });
    var token  = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ message: 'Account created!', token,
      user: { id: user._id, name, email: user.email, isPremium: false } });
  } catch(err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// LOGIN
app.post('/api/login', async function(req, res) {
  try {
    var email = req.body.email, password = req.body.password;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    var user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !await bcrypt.compare(password, user.password))
      return res.status(400).json({ error: 'Invalid email or password' });
    var token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login successful!', token,
      user: { id: user._id, name: user.name, email: user.email, isPremium: user.isPremium, premiumExpiry: user.premiumExpiry } });
  } catch(err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// PROFILE
app.get('/api/profile', authenticate, async function(req, res) {
  try {
    var user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch(err) { res.status(500).json({ error: 'Server error' }); }
});

// CREATE ORDER
app.post('/api/create-order', authenticate, async function(req, res) {
  try {
    var userId = req.user.id;
    var user   = await User.findById(userId);
    if (user.isPremium) return res.status(400).json({ error: 'Already Premium!' });

    await Order.deleteMany({ userId: userId, status: 'pending' });

    var shortId = userId.toString().slice(-4).toUpperCase();
    var billRef = 'USR-' + shortId + '-' + Date.now();
    var mId     = process.env.MERCHANT_ID   || '256792';
    var mName   = process.env.MERCHANT_NAME || 'CHAMROEUN BY C.CHET';

    var qrString  = generateKHQR(mId, mName, 5.00, billRef);
    var md5Hash   = crypto.createHash('md5').update(qrString).digest('hex');

    var order = await Order.create({ billRef, userId, amount: 5.00, qrString, md5Hash });

    var qrImageUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=220x220&margin=10&data=' + encodeURIComponent(qrString);

    console.log('[ORDER] ' + billRef + ' | md5: ' + md5Hash.slice(0,8) + '...');

    startBakongPolling(order._id, md5Hash, billRef);

    res.json({ success: true, billRef, amount: '5.00', qrImageUrl, md5Hash,
      merchantName: mName });
  } catch(err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// TELEGRAM WEBHOOK
app.post('/api/telegram-webhook', async function(req, res) {
  try {
    var text = (req.body && req.body.message && req.body.message.text) || '';
    var billMatch   = text.match(/USR-([A-Z0-9]{4})-(\d+)/);
    var amountMatch = text.match(/\$(\d+\.?\d*)/);
    if (!billMatch) return res.json({ ok: true });
    var billRef = billMatch[0];
    var amount  = amountMatch ? parseFloat(amountMatch[1]) : 0;
    var order   = await Order.findOne({ billRef: billRef, status: 'pending' });
    if (order && Math.abs(amount - 5.00) < 0.01) await activatePremium(order);
    res.json({ ok: true });
  } catch(err) { console.error(err); res.json({ ok: true }); }
});

// ORDER STATUS
app.get('/api/order-status/:billRef', authenticate, async function(req, res) {
  try {
    var order = await Order.findOne({ billRef: req.params.billRef });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json({ status: order.status, billRef: order.billRef });
  } catch(err) { res.status(500).json({ error: 'Server error' }); }
});

// START
var PORT = process.env.PORT || 5000;
server.listen(PORT, function() {
  console.log('[START] Server running on port ' + PORT);
  console.log('[INFO] Merchant: ' + (process.env.MERCHANT_NAME || 'CHAMROEUN by C.CHET'));
  console.log('[INFO] Bakong Token: ' + (process.env.BAKONG_TOKEN ? 'SET' : 'NOT SET'));
});
