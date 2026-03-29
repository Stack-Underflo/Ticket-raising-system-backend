/*
  ═══════════════════════════════════════════════
  BMSIT&M Placement Portal — Backend
  server.js

  Stack: Express + Mongoose (MongoDB) + sessions
  Auth:  Simple session-based (no JWT for now).
         To upgrade to JWT later: swap the
         session blocks for jwt.sign/jwt.verify.
  ═══════════════════════════════════════════════
*/

require('dotenv').config();
const express      = require('express');
const mongoose     = require('mongoose');
const cors         = require('cors');
const bcrypt       = require('bcryptjs');
const session      = require('express-session');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── MIDDLEWARE ───────────────────────────────
app.use(express.json());
app.use(cors({
  origin: process.env.ticket-raising-system-frontend.vercel.app,
  credentials: true,
}));
app.use(session({
  secret:            process.env.SESSION_SECRET || 'dev_secret',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge:   8 * 60 * 60 * 1000,  // 8 hours
    // secure: true  ← uncomment this when you deploy to HTTPS on Azure
  },
}));

// ─── DATABASE CONNECTION ──────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅  MongoDB connected'))
  .catch(err => { console.error('❌  MongoDB error:', err.message); process.exit(1); });

// ─── SCHEMAS & MODELS ────────────────────────

// USER
const userSchema = new mongoose.Schema({
  name:      { type: String, required: true },
  email:     { type: String, required: true, unique: true, lowercase: true },
  password:  { type: String, required: true },      // bcrypt hash
  role:      { type: String, enum: ['student', 'admin'], default: 'student' },
  usn:       { type: String },                       // only for students
  dept:      { type: String },
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model('User', userSchema);

// TICKET
const ticketSchema = new mongoose.Schema({
  ticketId:  { type: String, required: true, unique: true },
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name:      String,
  usn:       String,
  dept:      String,
  email:     String,
  phone:     String,
  sem:       String,
  category:  String,
  priority:  { type: String, enum: ['Low','Medium','High','Urgent'], default: 'Low' },
  title:     String,
  desc:      String,
  company:   String,
  fileName:  String,
  status:    { type: String, enum: ['Open','In Progress','Resolved','Closed'], default: 'Open' },
  adminNote: { type: String, default: '' },          // placement cell can add notes
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});
const Ticket = mongoose.model('Ticket', ticketSchema);

// ─── HELPERS ─────────────────────────────────

// Generate ticket ID: TKT-YEAR + 4-digit counter
async function generateTicketId() {
  const year  = new Date().getFullYear();
  const count = await Ticket.countDocuments();
  return `TKT-${year}${String(count + 1).padStart(4, '0')}`;
}

// Route guard: must be logged in
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}

// Route guard: must be admin
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  next();
}

// ─── AUTH ROUTES ─────────────────────────────

// POST /api/auth/register
// Creates a student account.
// To create an admin, add  "role": "admin"  to the body (restrict this in production).
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role, usn, dept } = req.body;

    if (!name || !email || !password)
      return res.status(400).json({ error: 'Name, email and password are required' });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hash, role: role || 'student', usn, dept });

    res.status(201).json({ message: 'Registered successfully', userId: user._id, role: user.role });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    // Store identity in session
    req.session.userId = user._id;
    req.session.role   = user.role;
    req.session.name   = user.name;

    res.json({
      message: 'Logged in',
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: 'Logged out' }));
});

// GET /api/auth/me  — frontend calls this on page load to check if session exists
app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId)
    return res.status(401).json({ loggedIn: false });
  res.json({
    loggedIn: true,
    user: { id: req.session.userId, name: req.session.name, role: req.session.role }
  });
});

// ─── TICKET ROUTES ───────────────────────────

// POST /api/tickets  — raise a ticket (students only)
app.post('/api/tickets', requireAuth, async (req, res) => {
  try {
    if (req.session.role === 'admin')
      return res.status(403).json({ error: 'Admins cannot raise tickets' });

    const ticketId = await generateTicketId();
    const ticket   = await Ticket.create({ ...req.body, ticketId, userId: req.session.userId });
    res.status(201).json({ message: 'Ticket created', ticketId: ticket.ticketId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/tickets/my  — student sees only their own tickets
app.get('/api/tickets/my', requireAuth, async (req, res) => {
  try {
    const tickets = await Ticket.find({ userId: req.session.userId }).sort({ createdAt: -1 });
    res.json(tickets);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/tickets/:id  — get one ticket (student: own only; admin: any)
app.get('/api/tickets/:id', requireAuth, async (req, res) => {
  try {
    const ticket = await Ticket.findOne({ ticketId: req.params.id });
    if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

    // Students can only view their own
    if (req.session.role !== 'admin' && String(ticket.userId) !== String(req.session.userId))
      return res.status(403).json({ error: 'Access denied' });

    res.json(ticket);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/tickets  — admin sees ALL tickets, with optional filters
app.get('/api/tickets', requireAdmin, async (req, res) => {
  try {
    const filter = {};
    if (req.query.status)   filter.status   = req.query.status;
    if (req.query.priority) filter.priority = req.query.priority;
    if (req.query.category) filter.category = req.query.category;

    const tickets = await Ticket.find(filter).sort({ createdAt: -1 });
    res.json(tickets);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/tickets/:id  — admin updates status / adds note
app.patch('/api/tickets/:id', requireAdmin, async (req, res) => {
  try {
    const allowed = ['status', 'adminNote', 'priority'];   // fields admin can change
    const update  = {};
    allowed.forEach(f => { if (req.body[f] !== undefined) update[f] = req.body[f]; });
    update.updatedAt = new Date();

    const ticket = await Ticket.findOneAndUpdate(
      { ticketId: req.params.id },
      { $set: update },
      { new: true }
    );
    if (!ticket) return res.status(404).json({ error: 'Ticket not found' });
    res.json({ message: 'Updated', ticket });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/stats  — dashboard counts for admin
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const [total, open, inProgress, resolved, closed] = await Promise.all([
      Ticket.countDocuments(),
      Ticket.countDocuments({ status: 'Open' }),
      Ticket.countDocuments({ status: 'In Progress' }),
      Ticket.countDocuments({ status: 'Resolved' }),
      Ticket.countDocuments({ status: 'Closed' }),
    ]);
    res.json({ total, open, inProgress, resolved, closed });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── START SERVER ────────────────────────────
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

mongoose.connection.on("connected", () => {
  console.log("✅ MongoDB CONNECTED");
});
