require('dotenv').config();
const express   = require('express');
const mongoose  = require('mongoose');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');
const http      = require('http');
const { Server } = require('socket.io');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

// ── Middleware ──────────────────────────────────────────
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
  amount:    { type: String, default: '5.00' },
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
    console.log(`🔌 User ${userId} connected via WebSocket`);
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

// ── Telegram Helper ─────────────────────────────────────
async function sendTelegramMsg(chatId, text) {
  if (!process.env.BOT_TOKEN || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'Markdown' })
    });
  } catch (e) { console.error('Telegram error:', e.message); }
}

// ── Routes ──────────────────────────────────────────────

app.get('/', (req, res) => res.json({ status: 'MD Quiz Platform API running ✅' }));

// REGISTER
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'All fields are required' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already registered' });
    const hashed = await bcrypt.hash(password, 12);
    const user   = await User.create({ name, email, password: hashed });
    const token  = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ message: 'Account created successfully!', token,
      user: { id: user._id, name: user.name, email: user.email, isPremium: user.isPremium } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const user  = await User.findOne({ email });
    if (!user)  return res.status(400).json({ error: 'Invalid email or password' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login successful!', token,
      user: { id: user._id, name: user.name, email: user.email, isPremium: user.isPremium, premiumExpiry: user.premiumExpiry } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// PROFILE
app.get('/api/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// CREATE ORDER — generate Bill Reference linked to User
app.post('/api/create-order', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const user   = await User.findById(userId);
    if (user.isPremium) return res.status(400).json({ error: 'Already Premium!' });

    // Cancel old pending orders
    await Order.deleteMany({ userId, status: 'pending' });

    // Bill Reference: USR-{last4ofUserId}-{timestamp}
    const shortId = userId.toString().slice(-4).toUpperCase();
    const billRef = `USR-${shortId}-${Date.now()}`;

    await Order.create({ billRef, userId, amount: '5.00' });

    console.log(`📋 Order created: ${billRef}`);
    res.json({
      success: true,
      billRef,
      amount: '5.00',
      merchantName: process.env.MERCHANT_NAME || 'CHAMROEUN by C.CHET',
      note: `សូមទូទាត់ $5.00 ហើយ Screenshot ផ្ញើទៅ Bot ជាមួយ Ref: ${billRef}`
    });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// TELEGRAM WEBHOOK — receives forwarded ABA PayWay messages
app.post('/api/telegram-webhook', async (req, res) => {
  try {
    const { message } = req.body;
    if (!message?.text) return res.json({ ok: true });

    const text = message.text;
    console.log('📨 Telegram:', text.substring(0, 100));

    // Look for Bill Reference in message
    const billMatch   = text.match(/USR-([A-Z0-9]{4})-(\d+)/);
    const amountMatch = text.match(/\$(\d+\.?\d*)/);
    if (!billMatch) return res.json({ ok: true });

    const billRef = billMatch[0];
    const amount  = amountMatch ? parseFloat(amountMatch[1]) : 0;

    const order = await Order.findOne({ billRef, status: 'pending' });
    if (!order) {
      await sendTelegramMsg(process.env.ADMIN_CHAT_ID,
        `⚠️ Payment $${amount} received\nRef: ${billRef}\nBut no matching order found.`);
      return res.json({ ok: true });
    }

    if (Math.abs(amount - 5.00) > 0.01) {
      await sendTelegramMsg(process.env.ADMIN_CHAT_ID, `⚠️ Wrong amount $${amount} for ${billRef}`);
      return res.json({ ok: true });
    }

    // ✅ Activate Premium
    await User.findByIdAndUpdate(order.userId, {
      isPremium:     true,
      premiumExpiry: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
    });
    await Order.findByIdAndUpdate(order._id, { status: 'completed' });

    // Notify user via WebSocket (real-time popup)
    notifyUser(order.userId, 'payment_confirmed', {
      message: 'ការទូទាត់បានបញ្ជាក់! Quiz Unlocked!',
      billRef
    });

    // Log to Admin Telegram
    const user = await User.findById(order.userId);
    await sendTelegramMsg(process.env.ADMIN_CHAT_ID,
      `✅ *Payment Confirmed!*\n👤 ${user.name} (${user.email})\n💰 $${amount}\n📋 ${billRef}\n🎓 Premium Activated!`
    );

    console.log(`✅ Premium activated: ${order.userId}`);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.json({ ok: true }); }
});

// CHECK ORDER STATUS (polling fallback)
app.get('/api/order-status/:billRef', authenticate, async (req, res) => {
  try {
    const order = await Order.findOne({ billRef: req.params.billRef });
    if (!order) return res.status(404).json({ error: 'Not found' });
    res.json({ status: order.status });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// ── Start ───────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
