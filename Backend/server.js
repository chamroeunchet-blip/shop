require('dotenv').config();
const express    = require('express');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const http       = require('http');
const crypto     = require('crypto');
const { Server } = require('socket.io');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

app.use(cors({ origin: '*' }));
app.use(express.json());

// ── MongoDB ─────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

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
io.on('connection', (socket) => {
  socket.on('register', (userId) => {
    connectedUsers.set(userId.toString(), socket.id);
    console.log('🔌 User connected:', userId);
  });
  socket.on('disconnect', () => {
    for (const [uid, sid] of connectedUsers.entries()) {
      if (sid === socket.id) { connectedUsers.delete(uid); break; }
    }
  });
});

function notifyUser(userId, event, data) {
  const sid = connectedUsers.get(userId.toString());
  if (sid) io.to(sid).emit(event, data);
}

// ── Auth Middleware ─────────────────────────────────────
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ── CRC16 for KHQR ──────────────────────────────────────
function crc16(str) {
  let crc = 0xFFFF;
  for (let i = 0; i < str.length; i++) {
    crc ^= str.charCodeAt(i) << 8;
    for (let j = 0; j < 8; j++) {
      crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1);
    }
  }
  return (crc & 0xFFFF).toString(16).toUpperCase().padStart(4, '0');
}

// ── Generate KHQR String (EMVCo Standard) ───────────────
function generateKHQR({ merchantId, merchantName, amount, billRef }) {
  const enc = (id, val) => {
    const v = String(val);
    return `${id}${String(v.length).padStart(2, '0')}${v}`;
  };

  // Merchant Account Info — tag 29 (KHQR/ABA format)
  const acctInfo = enc('00', 'A000000440') +
                   enc('01', merchantId) +
                   enc('02', billRef);
  const tag29 = enc('29', acctInfo);

  // Additional Data Field — bill reference in tag 05
  const addData = enc('05', billRef);
  const tag62   = enc('62', addData);

  // Build full QR body
  const body =
    enc('00', '01') +           // Payload format indicator
    enc('01', '12') +           // Dynamic QR
    tag29 +                     // Merchant account info
    enc('52', '5999') +         // Merchant category code
    enc('53', '840') +          // Currency: USD
    enc('54', amount.toFixed(2)) + // Amount
    enc('58', 'KH') +           // Country code
    enc('59', merchantName.substring(0, 25)) + // Merchant name
    enc('60', 'PHNOM PENH') +   // Merchant city
    tag62 +                     // Additional data
    '6304';                     // CRC placeholder

  return body + crc16(body);
}

// ── Bakong API: Check Transaction ───────────────────────
async function checkBakongTransaction(md5Hash) {
  if (!process.env.BAKONG_TOKEN) {
    console.log('⚠️ BAKONG_TOKEN not set');
    return null;
  }
  try {
    const baseUrl = 'https://api-bakong.nbc.org.kh';
    const res = await fetch(`${baseUrl}/v1/check_transaction_by_md5`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.BAKONG_TOKEN}`,
        'Content-Type':  'application/json'
      },
      body: JSON.stringify({ md5: md5Hash })
    });
    const data = await res.json();
    console.log(`🔍 Bakong check [${md5Hash.slice(0,8)}...]: code=${data.responseCode} msg=${data.responseMessage}`);
    return data;
  } catch (err) {
    console.error('❌ Bakong API error:', err.message);
    return null;
  }
}

// ── Telegram Notification ───────────────────────────────
async function sendTelegram(chatId, text) {
  if (!process.env.BOT_TOKEN || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'Markdown' })
    });
  } catch (e) { console.error('TG error:', e.message); }
}

// ── Activate Premium ────────────────────────────────────
async function activatePremium(order) {
  // Prevent double activation
  const fresh = await Order.findById(order._id);
  if (!fresh || fresh.status === 'completed') return;

  const expiry = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
  await User.findByIdAndUpdate(order.userId, {
    isPremium: true,
    premiumExpiry: expiry
  });
  await Order.findByIdAndUpdate(order._id, { status: 'completed' });

  // Real-time notify via WebSocket
  notifyUser(order.userId, 'payment_confirmed', {
    message: 'ការទូទាត់បានបញ្ជាក់! Quiz Unlocked!',
    billRef: order.billRef
  });

  // Log to Telegram admin
  const user = await User.findById(order.userId);
  await sendTelegram(process.env.ADMIN_CHAT_ID,
    `✅ *Payment Confirmed!*\n` +
    `👤 ${user?.name} (${user?.email})\n` +
    `💰 $${order.amount}\n` +
    `📋 ${order.billRef}\n` +
    `🎓 MD Quiz Premium Activated!\n` +
    `📅 Expires: ${expiry.toLocaleDateString('km-KH')}`
  );

  console.log(`✅ Premium activated for user: ${order.userId}`);
}

// ── Bakong Polling (every 5s, max 10 min) ───────────────
function startBakongPolling(orderId, md5Hash, billRef) {
  let attempts = 0;
  const MAX    = 120; // 120 x 5s = 10 minutes

  const timer = setInterval(async () => {
    attempts++;

    // Stop if exceeded max time
    if (attempts > MAX) {
      clearInterval(timer);
      await Order.findByIdAndUpdate(orderId, { status: 'expired' });
      console.log(`⏰ Order expired: ${billRef}`);
      return;
    }

    // Check if already handled (by Telegram webhook)
    const order = await Order.findById(orderId);
    if (!order || order.status !== 'pending') {
      clearInterval(timer);
      return;
    }

    // Call Bakong API
    const result = await checkBakongTransaction(md5Hash);
    if (!result) return;

    if (result.responseCode === 0 && result.data) {
      // Payment confirmed!
      clearInterval(timer);
      console.log(`💰 Payment confirmed: ${billRef}`);
      console.log(`   From: ${result.data.fromAccountId}`);
      console.log(`   Amount: ${result.data.amount} ${result.data.currency}`);
      await activatePremium(order);
    }
    // responseCode === 1 = not found yet, keep polling

  }, 5000);
}

// ════════════════════════════════════════════════════════
// ── ROUTES ──────────────────────────────────────────────
// ════════════════════════════════════════════════════════

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'MD Quiz API ✅', time: new Date().toISOString() });
});

// ── REGISTER ────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (await User.findOne({ email }))
      return res.status(400).json({ error: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 12);
    const user   = await User.create({ name, email, password: hashed });
    const token  = jwt.sign({ id: user._id, email }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'Account created successfully!',
      token,
      user: { id: user._id, name, email, isPremium: false }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── LOGIN ────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password))
      return res.status(400).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user._id, email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({
      message: 'Login successful!',
      token,
      user: { id: user._id, name: user.name, email, isPremium: user.isPremium, premiumExpiry: user.premiumExpiry }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── PROFILE ──────────────────────────────────────────────
app.get('/api/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── CREATE ORDER + DYNAMIC KHQR ─────────────────────────
app.post('/api/create-order', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const user   = await User.findById(userId);

    if (user.isPremium)
      return res.status(400).json({ error: 'Already Premium!' });

    // Cancel old pending orders
    await Order.deleteMany({ userId, status: 'pending' });

    // Generate unique Bill Reference
    const shortId = userId.toString().slice(-4).toUpperCase();
    const billRef = `USR-${shortId}-${Date.now()}`;

    // Generate KHQR string with billRef embedded
    const qrString = generateKHQR({
      merchantId:   process.env.MERCHANT_ID   || '256792',
      merchantName: process.env.MERCHANT_NAME || 'CHAMROEUN BY C.CHET',
      amount:       5.00,
      billRef
    });

    // MD5 hash → used to check payment with Bakong API
    const md5Hash = crypto.createHash('md5').update(qrString).digest('hex');

    // Save order to DB
    const order = await Order.create({
      billRef,
      userId,
      amount:    5.00,
      qrString,
      md5Hash,
      status:    'pending'
    });

    // Generate QR image URL
    const qrImageUrl = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&margin=10&data=${encodeURIComponent(qrString)}`;

    console.log(`📋 New Order: ${billRef}`);
    console.log(`🔑 MD5: ${md5Hash}`);
    console.log(`📱 QR String length: ${qrString.length}`);

    // Start polling Bakong API every 5s
    startBakongPolling(order._id, md5Hash, billRef);

    res.json({
      success: true,
      billRef,
      amount: '5.00',
      qrImageUrl,
      md5Hash,
      merchantName: process.env.MERCHANT_NAME || 'CHAMROEUN by C.CHET'
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── TELEGRAM WEBHOOK (fallback detection) ───────────────
app.post('/api/telegram-webhook', async (req, res) => {
  try {
    const text = req.body?.message?.text || '';
    console.log('📨 Telegram msg:', text.substring(0, 100));

    const billMatch   = text.match(/USR-([A-Z0-9]{4})-(\d+)/);
    const amountMatch = text.match(/\$(\d+\.?\d*)/);

    if (!billMatch) return res.json({ ok: true });

    const billRef = billMatch[0];
    const amount  = amountMatch ? parseFloat(amountMatch[1]) : 0;

    console.log(`🔍 Telegram: billRef=${billRef} amount=$${amount}`);

    const order = await Order.findOne({ billRef, status: 'pending' });
    if (order && Math.abs(amount - 5.00) < 0.01) {
      await activatePremium(order);
    } else if (!order) {
      await sendTelegram(process.env.ADMIN_CHAT_ID,
        `⚠️ Payment $${amount} received but no matching order found.\nRef: ${billRef}`);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.json({ ok: true });
  }
});

// ── CHECK ORDER STATUS ───────────────────────────────────
app.get('/api/order-status/:billRef', authenticate, async (req, res) => {
  try {
    const order = await Order.findOne({ billRef: req.params.billRef });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json({ status: order.status, billRef: order.billRef });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── START SERVER ─────────────────────────────────────────
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🏦 Merchant: ${process.env.MERCHANT_NAME || 'CHAMROEUN by C.CHET'}`);
  console.log(`🔑 Bakong Token: ${process.env.BAKONG_TOKEN ? '✅ Set' : '⚠️ Not set'}`);
});
