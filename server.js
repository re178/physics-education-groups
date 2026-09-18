'use strict';

/**
 * ============================================================================
 * PHYSICS EDUCATION GROUPS — Complete Backend (server.js)
 * ============================================================================
 *
 * This single file contains the ENTIRE backend:
 *
 *   1. Environment loading + validation
 *   2. MongoDB / Mongoose connection (with retry, index sync, shutdown)
 *   3. Mongoose models: Group, Member, Admin, AdminSession
 *   4. Utilities: normalization, validation, phone, password hashing
 *   5. Middleware: Helmet, CORS, rate limiting, CSRF, auth, error handler
 *   6. Services: registration, group ops, member ops, admin ops, export
 *   7. Routes: public, member, admin, SSE events
 *   8. Static file serving for /public
 *   9. Graceful startup and shutdown
 *
 * No frameworks beyond Express. No React. No Firebase. No MySQL.
 * Deployable to Render with `npm start`.
 *
 * Author: Physics Education Groups
 * ============================================================================
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');

// ============================================================================
// SECTION 1 — ENVIRONMENT
// ============================================================================

(function loadDotenv() {
  try {
    const dotenv = require('dotenv');
    const envPath = path.resolve(process.cwd(), '.env');
    if (fs.existsSync(envPath)) {
      const result = dotenv.config({ path: envPath });
      if (result.error) {
        console.warn('[env] Warning: could not load .env —', result.error.message);
      }
    }
  } catch (_) {
    console.warn('[env] dotenv not available, using process.env only.');
  }
})();

const readString = (key, fallback = '') => {
  const v = process.env[key];
  if (v === undefined || v === null) return fallback;
  return String(v).trim();
};

const readBool = (key, fallback = false) => {
  const v = readString(key, String(fallback)).toLowerCase();
  if (['1', 'true', 'yes', 'on', 'enabled'].includes(v)) return true;
  if (['0', 'false', 'no', 'off', 'disabled', ''].includes(v)) return false;
  return fallback;
};

const readInt = (key, fallback = 0) => {
  const v = readString(key, String(fallback));
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
};

const readList = (key, fallback = []) => {
  const v = readString(key, '');
  if (!v) return fallback;
  return v.split(',').map((s) => s.trim()).filter(Boolean);
};

const NODE_ENV = readString('NODE_ENV', 'development') || 'development';
const IS_PROD = NODE_ENV === 'production';
const IS_DEV = NODE_ENV === 'development';

const PORT = readInt('PORT', 10000);
const MONGODB_URI = readString('MONGODB_URI');
const ADMIN_USERNAME = readString('ADMIN_USERNAME', 'administrator123');
const ADMIN_PASSWORD = readString('ADMIN_PASSWORD', '1234567890');
const SESSION_SECRET_RAW = readString('SESSION_SECRET');
const CORS_ORIGIN = readList('CORS_ORIGIN', []);
const STORE_IP_HASH = readBool('STORE_IP_HASH', false);
const ENFORCE_DEVICE_LOCK = readBool('ENFORCE_DEVICE_LOCK', true);

// Fallbacks + validation
if (!MONGODB_URI) {
  console.error('\n[env] FATAL: MONGODB_URI is required. Set it in .env or Render env vars.\n');
  process.exit(1);
}
if (!/^mongodb(\+srv)?:\/\//i.test(MONGODB_URI)) {
  console.error('\n[env] FATAL: MONGODB_URI must start with mongodb:// or mongodb+srv://\n');
  process.exit(1);
}
if (IS_PROD && (!SESSION_SECRET_RAW || SESSION_SECRET_RAW.length < 24)) {
  console.error('\n[env] FATAL: SESSION_SECRET (>=24 chars) is required in production.\n');
  process.exit(1);
}

const SESSION_SECRET =
  SESSION_SECRET_RAW && SESSION_SECRET_RAW.length >= 24
    ? SESSION_SECRET_RAW
    : crypto.randomBytes(48).toString('hex');

const CONFIG = Object.freeze({
  NODE_ENV,
  IS_PROD,
  IS_DEV,
  PORT,
  MONGODB_URI,
  ADMIN_USERNAME,
  ADMIN_PASSWORD,
  SESSION_SECRET,
  CORS_ORIGIN,
  STORE_IP_HASH,
  ENFORCE_DEVICE_LOCK,
  MAX_GROUP_MEMBERS: 10,
  ADMIN_COOKIE: 'peg_admin_sid',
  MEMBER_COOKIE: 'peg_member_sid',
  CSRF_COOKIE: 'peg_csrf',
  CSRF_HEADER: 'x-csrf-token',
  ADMIN_SESSION_TTL_MS: 8 * 60 * 60 * 1000,
  MEMBER_SESSION_TTL_MS: 12 * 60 * 60 * 1000,
  CSRF_TTL_MS: 4 * 60 * 60 * 1000,
  COOKIE_SECURE: IS_PROD,
  COOKIE_SAME_SITE: 'strict',
});

console.log(`[boot] Physics Education Groups starting in ${NODE_ENV} mode on port ${PORT}.`);

// ============================================================================
// SECTION 2 — UTILITIES (normalization, validation, hashing)
// ============================================================================

/**
 * Normalize a group name for comparison:
 *   "  Group A  " → "group a"
 *   "GROUP  A"   → "group a"  (multiple spaces collapsed)
 */
function normalizeGroupName(raw) {
  if (raw === null || raw === undefined) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '') // strip control chars
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

/** Preserve display casing but strip control chars and collapse whitespace. */
function displayGroupName(raw) {
  if (raw === null || raw === undefined) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Normalize regNo: trim, collapse internal whitespace, uppercase. */
function normalizeRegNo(raw) {
  if (raw === null || raw === undefined) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, '')
    .trim()
    .toUpperCase();
}

/** Normalize a person's name (trim + collapse whitespace). */
function normalizeName(raw) {
  if (raw === null || raw === undefined) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Normalize Kenyan phone numbers to E.164 (+2547XXXXXXXX or +2541XXXXXXXX).
 * Accepts:
 *   0712345678, 0700123456, 0112345678
 *   254712345678, 254112345678
 *   +254712345678, +254112345678
 * Returns null if invalid.
 */
function normalizePhone(raw) {
  if (raw === null || raw === undefined) return null;
  let s = String(raw).replace(/[\s\-().]/g, '');
  if (s.startsWith('+')) s = s.slice(1);
  if (/^254(7|1)\d{8}$/.test(s)) return '+' + s;
  if (/^0(7|1)\d{8}$/.test(s)) return '+254' + s.slice(1);
  return null;
}

/** Validate a device ID: alphanumeric with dashes, 8–128 chars. */
function isValidDeviceId(id) {
  if (!id || typeof id !== 'string') return false;
  const trimmed = id.trim();
  if (trimmed.length < 8 || trimmed.length > 128) return false;
  return /^[A-Za-z0-9_\-:]+$/.test(trimmed);
}

/** Validate group name: non-empty after normalization, <= 80 chars. */
function isValidGroupName(raw) {
  const n = normalizeGroupName(raw);
  if (!n) return false;
  if (n.length > 80) return false;
  return true;
}

/** Validate regNo: 3–40 chars after normalization, printable. */
function isValidRegNo(raw) {
  const n = normalizeRegNo(raw);
  if (n.length < 3 || n.length > 40) return false;
  return /^[A-Z0-9\-\/_.]+$/.test(n);
}

/** Validate full name: 2–120 chars. */
function isValidName(raw) {
  const n = normalizeName(raw);
  if (n.length < 2 || n.length > 120) return false;
  return /^[\p{L}\p{M}0-9 .,'\-()]+$/u.test(n);
}

/** Sanitize device metadata to a known-safe subset. */
function sanitizeDeviceMetadata(meta) {
  if (!meta || typeof meta !== 'object') return {};
  const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
  const str = (v, max = 200) => (typeof v === 'string' ? v.slice(0, max) : '');
  const bool = (v) => Boolean(v);

  const screen = meta.screen && typeof meta.screen === 'object' ? meta.screen : {};
  const viewport = meta.viewport && typeof meta.viewport === 'object' ? meta.viewport : {};

  return {
    userAgent: str(meta.userAgent, 500),
    platform: str(meta.platform, 120),
    language: str(meta.language, 60),
    languages: Array.isArray(meta.languages)
      ? meta.languages.filter((l) => typeof l === 'string').slice(0, 10)
      : [],
    timezone: str(meta.timezone, 80),
    screen: {
      width: num(screen.width),
      height: num(screen.height),
      colorDepth: num(screen.colorDepth),
      pixelRatio: num(screen.pixelRatio),
    },
    viewport: {
      width: num(viewport.width),
      height: num(viewport.height),
    },
    hardwareConcurrency: num(meta.hardwareConcurrency),
    deviceMemory: num(meta.deviceMemory),
    touchSupport: bool(meta.touchSupport),
    online: meta.online === undefined ? true : bool(meta.online),
    cookieEnabled: meta.cookieEnabled === undefined ? true : bool(meta.cookieEnabled),
    doNotTrack: str(meta.doNotTrack, 20),
  };
}

/** One-way hash of the client IP. Never store raw IPs. */
function hashIp(ip) {
  if (!ip) return null;
  return crypto.createHmac('sha256', SESSION_SECRET).update(String(ip)).digest('hex');
}

/** scrypt password hashing. */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  try {
    const candidate = crypto.scryptSync(password, salt, 64).toString('hex');
    const a = Buffer.from(candidate, 'hex');
    const b = Buffer.from(hash, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch (_) {
    return false;
  }
}

/** Compare two strings in constant time. */
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/** Async route wrapper. */
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/** Custom error with a code + HTTP status + user-facing message. */
class AppError extends Error {
  constructor(message, code = 'ERROR', status = 400) {
    super(message);
    this.code = code;
    this.status = status;
    this.expose = true;
  }
}

/** Standard success envelope. */
function ok(res, payload = {}, status = 200) {
  return res.status(status).json({ success: true, ...payload });
}

/** Standard error envelope. */
function fail(res, message, code = 'ERROR', status = 400) {
  return res.status(status).json({ success: false, message, code });
}

// ============================================================================
// SECTION 3 — DATABASE
// ============================================================================

mongoose.set('strictQuery', true);
mongoose.set('bufferCommands', false);

let supportsTransactions = false;

const CONNECT_OPTIONS = {
  maxPoolSize: IS_PROD ? 20 : 10,
  serverSelectionTimeoutMS: 15000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 15000,
  heartbeatFrequencyMS: 10000,
  retryWrites: true,
  appName: 'physics-education-groups',
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function connectWithRetry(attempt = 1) {
  const MAX = 5;
  try {
    console.log(`[db] Connecting (attempt ${attempt}/${MAX})...`);
    await mongoose.connect(MONGODB_URI, CONNECT_OPTIONS);
    return true;
  } catch (err) {
    console.error(`[db] Attempt ${attempt} failed: ${err.message}`);
    if (attempt >= MAX) throw err;
    const delay = 1500 * Math.pow(2, attempt - 1);
    console.warn(`[db] Retrying in ${Math.round(delay / 1000)}s...`);
    await sleep(delay);
    return connectWithRetry(attempt + 1);
  }
}

async function detectTransactionSupport() {
  try {
    const admin = mongoose.connection.db.admin();
    const info = await admin.command({ hello: 1 }).catch(() => null);
    if (!info) return false;
    return Boolean(info.setName) || info.msg === 'isdbgrid';
  } catch (_) {
    return false;
  }
}

async function connectDatabase() {
  if (mongoose.connection.readyState === 1) return mongoose.connection;

  mongoose.connection.on('connected', () => console.log('[db] MongoDB connected.'));
  mongoose.connection.on('disconnected', () => console.warn('[db] MongoDB disconnected.'));
  mongoose.connection.on('reconnected', () => console.log('[db] MongoDB reconnected.'));
  mongoose.connection.on('error', (err) => console.error('[db] Error:', err.message));

  await connectWithRetry();
  supportsTransactions = await detectTransactionSupport();
  console.log(`[db] Transactions: ${supportsTransactions ? 'ENABLED' : 'DISABLED'}`);

  // Sync indexes across all models.
  for (const name of mongoose.modelNames()) {
    try {
      await mongoose.model(name).syncIndexes();
    } catch (err) {
      console.warn(`[db] Index sync warning for ${name}:`, err.message);
    }
  }
  console.log('[db] Indexes synchronized.');

  return mongoose.connection;
}

async function disconnectDatabase() {
  try {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close(false);
      console.log('[db] Connection closed.');
    }
  } catch (err) {
    console.error('[db] Close error:', err.message);
  }
}

// ============================================================================
// SECTION 4 — MODELS
// ============================================================================

// ---------- Group ----------
const GroupSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Group name is required.'],
      trim: true,
      maxlength: [80, 'Group name cannot exceed 80 characters.'],
    },
    normalizedName: {
      type: String,
      required: true,
      unique: true,
      index: true,
      trim: true,
      lowercase: true,
    },
    leader: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Member',
      default: null,
    },
    memberCount: {
      type: Number,
      default: 0,
      min: 0,
      max: [CONFIG.MAX_GROUP_MEMBERS, `Group cannot exceed ${CONFIG.MAX_GROUP_MEMBERS} members.`],
    },
  },
  { timestamps: true, versionKey: false }
);

GroupSchema.virtual('isFull').get(function () {
  return this.memberCount >= CONFIG.MAX_GROUP_MEMBERS;
});
GroupSchema.virtual('availableSlots').get(function () {
  return Math.max(0, CONFIG.MAX_GROUP_MEMBERS - this.memberCount);
});
GroupSchema.set('toJSON', { virtuals: true });
GroupSchema.set('toObject', { virtuals: true });

const Group = mongoose.model('Group', GroupSchema);

// ---------- Member ----------
const DeviceMetadataSchema = new mongoose.Schema(
  {
    userAgent: { type: String, default: '', maxlength: 500 },
    platform: { type: String, default: '', maxlength: 120 },
    language: { type: String, default: '', maxlength: 60 },
    languages: { type: [String], default: [] },
    timezone: { type: String, default: '', maxlength: 80 },
    screen: {
      width: { type: Number, default: 0 },
      height: { type: Number, default: 0 },
      colorDepth: { type: Number, default: 0 },
      pixelRatio: { type: Number, default: 0 },
    },
    viewport: {
      width: { type: Number, default: 0 },
      height: { type: Number, default: 0 },
    },
    hardwareConcurrency: { type: Number, default: 0 },
    deviceMemory: { type: Number, default: 0 },
    touchSupport: { type: Boolean, default: false },
    online: { type: Boolean, default: true },
    cookieEnabled: { type: Boolean, default: true },
    doNotTrack: { type: String, default: '', maxlength: 20 },
  },
  { _id: false }
);

const MemberSchema = new mongoose.Schema(
  {
    regNo: {
      type: String,
      required: [true, 'Registration number is required.'],
      unique: true,
      index: true,
      trim: true,
      uppercase: true,
      minlength: [3, 'Registration number is too short.'],
      maxlength: [40, 'Registration number is too long.'],
    },
    name: {
      type: String,
      required: [true, 'Full name is required.'],
      trim: true,
      minlength: [2, 'Full name is too short.'],
      maxlength: [120, 'Full name is too long.'],
    },
    phone: {
      type: String,
      required: [true, 'Phone number is required.'],
      trim: true,
      maxlength: [20, 'Phone number is too long.'],
    },
    group: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Group',
      required: true,
      index: true,
    },
    isLeader: {
      type: Boolean,
      default: false,
      index: true,
    },
    deviceId: {
      type: String,
      default: null,
      trim: true,
      maxlength: 128,
    },
    deviceMetadata: {
      type: DeviceMetadataSchema,
      default: () => ({}),
    },
    ipHash: {
      type: String,
      default: null,
      select: false,
    },
  },
  { timestamps: true, versionKey: false }
);

MemberSchema.index(
  { deviceId: 1 },
  {
    unique: true,
    sparse: true,
    partialFilterExpression: { deviceId: { $type: 'string' } },
    name: 'uniq_deviceId_when_set',
  }
);

MemberSchema.index({ group: 1, createdAt: 1 });
MemberSchema.index({ group: 1, isLeader: -1, createdAt: 1 });

const Member = mongoose.model('Member', MemberSchema);

// ---------- Admin ----------
const AdminSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      index: true,
      trim: true,
      lowercase: true,
      minlength: 3,
      maxlength: 60,
    },
    passwordHash: { type: String, required: true, select: false },
    passwordSalt: { type: String, required: true, select: false },
    lastLoginAt: { type: Date, default: null },
    loginCount: { type: Number, default: 0, min: 0 },
  },
  { timestamps: true, versionKey: false }
);

const Admin = mongoose.model('Admin', AdminSchema);

// ---------- AdminSession ----------
const AdminSessionSchema = new mongoose.Schema(
  {
    token: {
      type: String,
      required: true,
      unique: true,
      index: true,
      minlength: 32,
      maxlength: 200,
    },
    role: {
      type: String,
      required: true,
      enum: ['admin', 'member'],
      index: true,
    },
    subjectId: { type: mongoose.Schema.Types.ObjectId, default: null },
    group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group', default: null },
    userAgent: { type: String, default: '', maxlength: 300 },
    expiresAt: {
      type: Date,
      required: true,
      index: { expires: 0 },
    },
  },
  { timestamps: true, versionKey: false }
);

const AdminSession = mongoose.model('AdminSession', AdminSessionSchema);

// ============================================================================
// SECTION 5 — BUSINESS HELPERS
// ============================================================================

/**
 * Ensure the group has exactly one leader if it is non-empty.
 * - If no leader and group has members → promote earliest member.
 * - If leader no longer belongs to the group → promote earliest member.
 * - If multiple leaders exist → keep only the assigned one.
 */
async function reconcileGroupLeader(groupId) {
  const group = await Group.findById(groupId);
  if (!group) return null;

  const members = await Member.find({ group: groupId }).sort({ createdAt: 1, _id: 1 });
  if (members.length === 0) {
    if (group.leader) {
      group.leader = null;
      await group.save();
    }
    return group;
  }

  let leaderId = group.leader;
  const leaderStillPresent =
    leaderId && members.some((m) => String(m._id) === String(leaderId));

  if (!leaderStillPresent) {
    leaderId = members[0]._id;
    group.leader = leaderId;
    await group.save();
  }

  // Enforce exactly one isLeader:true
  const leaderMember = members.find((m) => String(m._id) === String(leaderId));
  if (leaderMember && !leaderMember.isLeader) {
    await Member.updateOne({ _id: leaderMember._id }, { $set: { isLeader: true } });
  }
  await Member.updateMany(
    { group: groupId, _id: { $ne: leaderId }, isLeader: true },
    { $set: { isLeader: false } }
  );

  return group;
}

/** Recalculate and persist a group's memberCount from the members collection. */
async function recalcMemberCount(groupId) {
  const count = await Member.countDocuments({ group: groupId });
  await Group.updateOne({ _id: groupId }, { $set: { memberCount: count } });
  return count;
}

/** Public shape for a group returned to admins/members. */
function shapeGroup(group, extra = {}) {
  return {
    id: String(group._id),
    name: group.name,
    normalizedName: group.normalizedName,
    memberCount: group.memberCount,
    capacity: CONFIG.MAX_GROUP_MEMBERS,
    isFull: group.memberCount >= CONFIG.MAX_GROUP_MEMBERS,
    leader: group.leader ? String(group.leader) : null,
    createdAt: group.createdAt,
    updatedAt: group.updatedAt,
    ...extra,
  };
}

/** Public shape for a member. */
function shapeMember(member) {
  return {
    id: String(member._id),
    regNo: member.regNo,
    name: member.name,
    phone: member.phone,
    isLeader: Boolean(member.isLeader),
    role: member.isLeader ? 'GROUP LEADER' : 'MEMBER',
    groupId: String(member.group),
    createdAt: member.createdAt,
    updatedAt: member.updatedAt,
  };
}

// ============================================================================
// SECTION 6 — SSE (Server-Sent Events for live admin dashboard)
// ============================================================================

const sseClients = new Set();

function sseBroadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try {
      res.write(payload);
    } catch (_) {
      sseClients.delete(res);
    }
  }
}

// Heartbeat keeps proxies and Render from closing idle connections.
setInterval(() => {
  for (const res of sseClients) {
    try {
      res.write(`: ping ${Date.now()}\n\n`);
    } catch (_) {
      sseClients.delete(res);
    }
  }
}, 25000).unref();

// ============================================================================
// SECTION 7 — APP + MIDDLEWARE
// ============================================================================

const app = express();
app.set('trust proxy', 1); // Render terminates TLS in front of us.

// Helmet — CSP allows our own assets only.
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: IS_PROD ? [] : null,
      },
    },
    crossOriginEmbedderPolicy: false,
    hsts: IS_PROD
      ? { maxAge: 15552000, includeSubDomains: true, preload: false }
      : false,
    referrerPolicy: { policy: 'no-referrer' },
  })
);

// CORS — same-origin by default; allow explicit list.
app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true); // same-origin / curl
      if (CORS_ORIGIN.length === 0) return cb(null, false);
      return cb(null, CORS_ORIGIN.includes(origin));
    },
    credentials: true,
  })
);

// Body parsing (small limits).
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(cookieParser());

// Rate limiting.
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 400,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests. Please slow down.', code: 'RATE_LIMIT' },
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many registration attempts. Try again later.', code: 'RATE_LIMIT' },
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many login attempts. Try again later.', code: 'RATE_LIMIT' },
});

app.use('/api/', generalLimiter);

// CSRF: double-submit cookie. Token is issued by GET /api/csrf-token.
function requireCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const cookieToken = req.cookies ? req.cookies[CONFIG.CSRF_COOKIE] : null;
  const headerToken = req.get(CONFIG.CSRF_HEADER);
  if (!cookieToken || !headerToken || !safeEqual(cookieToken, headerToken)) {
    return fail(res, 'Invalid or missing CSRF token.', 'CSRF_INVALID', 403);
  }
  return next();
}
app.use('/api/', requireCsrf);

// Cookie helpers.
const cookieOpts = (maxAgeMs) => ({
  httpOnly: true,
  secure: CONFIG.COOKIE_SECURE,
  sameSite: CONFIG.COOKIE_SAME_SITE,
  maxAge: maxAgeMs,
  path: '/',
});

// Auth middlewares.
async function attachSession(req, res, next, cookieName, role) {
  try {
    const token = req.cookies ? req.cookies[cookieName] : null;
    if (!token) return next();
    const session = await AdminSession.findOne({
      token,
      role,
      expiresAt: { $gt: new Date() },
    }).lean();
    if (!session) return next();
    req._session = session;
    return next();
  } catch (err) {
    return next(err);
  }
}

function requireAdmin(req, res, next) {
  attachSession(req, res, () => {
    if (!req._session || req._session.role !== 'admin') {
      return fail(res, 'Administrator authentication required.', 'AUTH_REQUIRED', 401);
    }
    return next();
  }, CONFIG.ADMIN_COOKIE, 'admin');
}

function requireMember(req, res, next) {
  attachSession(req, res, () => {
    if (!req._session || req._session.role !== 'member') {
      return fail(res, 'Member authentication required.', 'AUTH_REQUIRED', 401);
    }
    return next();
  }, CONFIG.MEMBER_COOKIE, 'member');
}

// ============================================================================
// SECTION 8 — PUBLIC ROUTES
// ============================================================================

app.get('/api/health', (req, res) => {
  const states = ['disconnected', 'connected', 'connecting', 'disconnecting'];
  return ok(res, {
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    db: states[mongoose.connection.readyState] || 'unknown',
    transactions: supportsTransactions,
    version: '1.0.0',
  });
});

app.get('/api/csrf-token', (req, res) => {
  const token = crypto.randomBytes(24).toString('hex');
  res.cookie(CONFIG.CSRF_COOKIE, token, {
    httpOnly: false, // JS does not strictly need to read this; we return it in the body.
    secure: CONFIG.COOKIE_SECURE,
    sameSite: CONFIG.COOKIE_SAME_SITE,
    maxAge: CONFIG.CSRF_TTL_MS,
    path: '/',
  });
  return ok(res, { token });
});

/**
 * POST /api/register
 * Body: { regNo, name, phone, groupName, deviceId, deviceMetadata }
 */
app.post(
  '/api/register',
  registerLimiter,
  asyncHandler(async (req, res) => {
    const body = req.body || {};
    const regNo = normalizeRegNo(body.regNo);
    const name = normalizeName(body.name);
    const phoneRaw = body.phone;
    const groupDisplay = displayGroupName(body.groupName);
    const groupNorm = normalizeGroupName(body.groupName);
    const deviceId = typeof body.deviceId === 'string' ? body.deviceId.trim() : '';
    const deviceMetadata = sanitizeDeviceMetadata(body.deviceMetadata);

    // 1) Field validation
    if (!isValidRegNo(regNo)) {
      return fail(res, 'Please provide a valid registration number.', 'INVALID_REQNO', 400);
    }
    if (!isValidName(name)) {
      return fail(res, 'Please provide a valid full name.', 'INVALID_NAME', 400);
    }
    const phone = normalizePhone(phoneRaw);
    if (!phone) {
      return fail(res, 'Please provide a valid Kenyan phone number.', 'INVALID_PHONE', 400);
    }
    if (!isValidGroupName(groupNorm)) {
      return fail(res, 'Please provide a valid group name.', 'INVALID_GROUP', 400);
    }
    if (!isValidDeviceId(deviceId)) {
      return fail(res, 'Unable to identify this device. Please refresh and try again.', 'INVALID_DEVICE', 400);
    }

    // 2) Duplicate REG NO
    const existingReg = await Member.findOne({ regNo }).lean();
    if (existingReg) {
      console.log(`[register] rejected duplicate regNo=${regNo}`);
      return fail(
        res,
        'This registration number has already been registered. If you believe this is an error, please contact the Administrator.',
        'DUPLICATE_REGNO',
        409
      );
    }

    // 3) Device lock
    if (ENFORCE_DEVICE_LOCK) {
      const existingDevice = await Member.findOne({ deviceId }).lean();
      if (existingDevice) {
        console.log('[register] rejected duplicate device');
        return fail(
          res,
          'This device has already been used to submit registration details. If you believe this is an error, please contact the Administrator.',
          'DEVICE_USED',
          409
        );
      }
    }

    // 4) Find or create group
    let group = await Group.findOne({ normalizedName: groupNorm });
    let isNewGroup = false;

    if (!group) {
      try {
        group = await Group.create({
          name: groupDisplay,
          normalizedName: groupNorm,
          memberCount: 0,
        });
        isNewGroup = true;
        console.log(`[register] created group "${groupDisplay}"`);
      } catch (err) {
        if (err && err.code === 11000) {
          // Race: someone else created it first — reload.
          group = await Group.findOne({ normalizedName: groupNorm });
        } else {
          throw err;
        }
      }
    }

    if (!group) {
      return fail(res, 'We could not complete your registration. Please contact the Administrator.', 'GROUP_CREATE_FAILED', 500);
    }

    // 5) Atomic capacity increment — this is the hard gate.
    const incremented = await Group.findOneAndUpdate(
      { _id: group._id, memberCount: { $lt: CONFIG.MAX_GROUP_MEMBERS } },
      { $inc: { memberCount: 1 } },
      { new: true }
    );

    if (!incremented) {
      console.log(`[register] group full: ${group.normalizedName}`);
      return fail(
        res,
        'This group is already full. A group can have a maximum of 10 members. Please contact the Administrator or choose another group.',
        'GROUP_FULL',
        409
      );
    }

    // 6) Determine leader: first member of the group.
    const isLeader = incremented.memberCount === 1;

    // 7) Create the member.
    let member;
    try {
      member = await Member.create({
        regNo,
        name,
        phone,
        group: group._id,
        isLeader,
        deviceId: deviceId || null,
        deviceMetadata,
        ipHash: STORE_IP_HASH ? hashIp(req.ip) : null,
      });
    } catch (err) {
      // Roll back the atomic increment.
      await Group.updateOne({ _id: group._id }, { $inc: { memberCount: -1 } });

      if (err && err.code === 11000) {
        const keys = err.keyPattern || {};
        if (keys.regNo) {
          return fail(
            res,
            'This registration number has already been registered. If you believe this is an error, please contact the Administrator.',
            'DUPLICATE_REGNO',
            409
          );
        }
        if (keys.deviceId) {
          return fail(
            res,
            'This device has already been used to submit registration details. If you believe this is an error, please contact the Administrator.',
            'DEVICE_USED',
            409
          );
        }
      }
      throw err;
    }

    // 8) Assign leader on the group if this was the first member.
    if (isLeader) {
      await Group.updateOne({ _id: group._id, leader: null }, { $set: { leader: member._id } });
      await reconcileGroupLeader(group._id);
      console.log(`[register] leader assigned: ${regNo} → ${group.normalizedName}`);
    }

    // 9) Recompute count defensively (should match).
    const freshCount = await recalcMemberCount(group._id);

    // 10) Notify admin SSE listeners.
    const finalGroup = await Group.findById(group._id);
    sseBroadcast('registration', {
      member: shapeMember(member),
      group: shapeGroup(finalGroup),
      isNewGroup,
      isLeader,
    });

    // 11) Success response.
    console.log(`[register] success regNo=${regNo} group=${group.normalizedName} leader=${isLeader}`);

    const message = isLeader
      ? 'You are the first member to register for this group. You have been assigned as the Group Leader.'
      : 'Registration successful.';

    return ok(
      res,
      {
        message,
        isLeader,
        isNewGroup,
        member: shapeMember(member),
        group: shapeGroup(finalGroup, { memberCount: freshCount }),
      },
      201
    );
  })
);

// ============================================================================
// SECTION 9 — MEMBER ROUTES
// ============================================================================

app.post(
  '/api/member/login',
  loginLimiter,
  asyncHandler(async (req, res) => {
    const groupNorm = normalizeGroupName(req.body.groupName);
    const regNo = normalizeRegNo(req.body.regNo);

    if (!groupNorm || !regNo) {
      return fail(res, 'Group name and registration number are required.', 'VALIDATION', 400);
    }

    const group = await Group.findOne({ normalizedName: groupNorm });
    if (!group) {
      return fail(res, 'Invalid group name or registration number.', 'INVALID_CREDENTIALS', 401);
    }

    const member = await Member.findOne({ regNo, group: group._id });
    if (!member) {
      return fail(res, 'Invalid group name or registration number.', 'INVALID_CREDENTIALS', 401);
    }

    // Create member session.
    const token = crypto.randomBytes(48).toString('hex');
    await AdminSession.create({
      token,
      role: 'member',
      subjectId: member._id,
      group: group._id,
      userAgent: String(req.get('user-agent') || '').slice(0, 300),
      expiresAt: new Date(Date.now() + CONFIG.MEMBER_SESSION_TTL_MS),
    });

    res.cookie(CONFIG.MEMBER_COOKIE, token, cookieOpts(CONFIG.MEMBER_SESSION_TTL_MS));

    console.log(`[member-login] ${regNo} → ${group.normalizedName}`);

    return ok(res, {
      message: 'Login successful.',
      member: shapeMember(member),
      group: shapeGroup(group),
    });
  })
);

app.post(
  '/api/member/logout',
  asyncHandler(async (req, res) => {
    const token = req.cookies ? req.cookies[CONFIG.MEMBER_COOKIE] : null;
    if (token) {
      await AdminSession.deleteOne({ token, role: 'member' });
    }
    res.clearCookie(CONFIG.MEMBER_COOKIE, { path: '/' });
    return ok(res, { message: 'Logged out.' });
  })
);

app.get(
  '/api/member/me',
  requireMember,
  asyncHandler(async (req, res) => {
    const member = await Member.findById(req._session.subjectId);
    if (!member) {
      return fail(res, 'Session invalid.', 'SESSION_INVALID', 401);
    }
    const group = await Group.findById(member.group);
    return ok(res, {
      member: shapeMember(member),
      group: group ? shapeGroup(group) : null,
    });
  })
);

app.get(
  '/api/member/group',
  requireMember,
  asyncHandler(async (req, res) => {
    const member = await Member.findById(req._session.subjectId);
    if (!member) {
      return fail(res, 'Session invalid.', 'SESSION_INVALID', 401);
    }
    const group = await Group.findById(member.group);
    if (!group) {
      return fail(res, 'Group not found.', 'NOT_FOUND', 404);
    }

    // Server-side enforcement: only members of this group.
    const members = await Member.find({ group: group._id })
      .sort({ isLeader: -1, createdAt: 1 })
      .select('regNo name phone isLeader group createdAt')
      .lean();

    const leader = members.find((m) => m.isLeader) || null;

    return ok(res, {
      group: {
        ...shapeGroup(group),
        leaderName: leader ? leader.name : null,
        leaderRegNo: leader ? leader.regNo : null,
      },
      members: members.map((m) => ({
        id: String(m._id),
        regNo: m.regNo,
        name: m.name,
        phone: m.phone,
        isLeader: Boolean(m.isLeader),
        role: m.isLeader ? 'GROUP LEADER' : 'MEMBER',
        createdAt: m.createdAt,
      })),
      viewer: { regNo: member.regNo, name: member.name, isLeader: member.isLeader },
    });
  })
);

// ============================================================================
// SECTION 10 — ADMIN ROUTES
// ============================================================================

app.post(
  '/api/admin/login',
  loginLimiter,
  asyncHandler(async (req, res) => {
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!username || !password) {
      return fail(res, 'Username and password are required.', 'VALIDATION', 400);
    }

    let admin = await Admin.findOne({ username }).select('+passwordHash +passwordSalt');

    if (!admin) {
      // Bootstrap: only the env-defined credentials can create the admin.
      if (username !== ADMIN_USERNAME.toLowerCase() || !safeEqual(password, ADMIN_PASSWORD)) {
        console.warn(`[admin-login] rejected unknown user "${username}"`);
        return fail(res, 'Invalid administrator credentials.', 'INVALID_CREDENTIALS', 401);
      }

      const { salt, hash } = hashPassword(ADMIN_PASSWORD);
      admin = await Admin.create({
        username,
        passwordHash: hash,
        passwordSalt: salt,
      });
      admin = await Admin.findOne({ username }).select('+passwordHash +passwordSalt');
      console.log('[admin-login] bootstrap admin created.');
    } else {
      const valid = verifyPassword(password, admin.passwordSalt, admin.passwordHash);
      if (!valid) {
        console.warn(`[admin-login] bad password for "${username}"`);
        return fail(res, 'Invalid administrator credentials.', 'INVALID_CREDENTIALS', 401);
      }
    }

    // Update login stats.
    await Admin.updateOne(
      { _id: admin._id },
      { $set: { lastLoginAt: new Date() }, $inc: { loginCount: 1 } }
    );

    // Create session.
    const token = crypto.randomBytes(48).toString('hex');
    await AdminSession.create({
      token,
      role: 'admin',
      userAgent: String(req.get('user-agent') || '').slice(0, 300),
      expiresAt: new Date(Date.now() + CONFIG.ADMIN_SESSION_TTL_MS),
    });

    res.cookie(CONFIG.ADMIN_COOKIE, token, cookieOpts(CONFIG.ADMIN_SESSION_TTL_MS));

    console.log(`[admin-login] success for "${username}"`);

    return ok(res, {
      message: 'Login successful.',
      admin: { username: admin.username, lastLoginAt: admin.lastLoginAt },
    });
  })
);

app.post(
  '/api/admin/logout',
  asyncHandler(async (req, res) => {
    const token = req.cookies ? req.cookies[CONFIG.ADMIN_COOKIE] : null;
    if (token) {
      await AdminSession.deleteOne({ token, role: 'admin' });
    }
    res.clearCookie(CONFIG.ADMIN_COOKIE, { path: '/' });
    return ok(res, { message: 'Logged out.' });
  })
);

app.get(
  '/api/admin/me',
  requireAdmin,
  asyncHandler(async (req, res) => {
    return ok(res, { authenticated: true });
  })
);

app.get(
  '/api/admin/dashboard',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const [totalMembers, totalGroups, totalLeaders] = await Promise.all([
      Member.countDocuments(),
      Group.countDocuments(),
      Member.countDocuments({ isLeader: true }),
    ]);

    const groups = await Group.find().sort({ createdAt: 1 }).lean();
    const leaders = await Member.find({ isLeader: true })
      .select('regNo name group')
      .lean();
    const leaderByGroup = {};
    for (const l of leaders) {
      leaderByGroup[String(l.group)] = { regNo: l.regNo, name: l.name };
    }

    const recent = await Member.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('group', 'name')
      .lean();

    return ok(res, {
      totals: { totalMembers, totalGroups, totalLeaders },
      groups: groups.map((g) =>
        shapeGroup(g, {
          leaderName: leaderByGroup[String(g._id)]?.name || null,
          leaderRegNo: leaderByGroup[String(g._id)]?.regNo || null,
        })
      ),
      recent: recent.map((m) => ({
        id: String(m._id),
        regNo: m.regNo,
        name: m.name,
        phone: m.phone,
        isLeader: Boolean(m.isLeader),
        role: m.isLeader ? 'GROUP LEADER' : 'MEMBER',
        groupName: m.group ? m.group.name : null,
        createdAt: m.createdAt,
      })),
    });
  })
);

app.get(
  '/api/admin/groups',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const groups = await Group.find().sort({ createdAt: 1 }).lean();
    const leaders = await Member.find({ isLeader: true }).select('regNo name group').lean();
    const leaderByGroup = {};
    for (const l of leaders) leaderByGroup[String(l.group)] = { regNo: l.regNo, name: l.name };
    return ok(res, {
      groups: groups.map((g) =>
        shapeGroup(g, {
          leaderName: leaderByGroup[String(g._id)]?.name || null,
          leaderRegNo: leaderByGroup[String(g._id)]?.regNo || null,
        })
      ),
    });
  })
);

app.get(
  '/api/admin/groups/:id',
  requireAdmin,
  asyncHandler(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return fail(res, 'Invalid group ID.', 'INVALID_ID', 400);
    }
    const group = await Group.findById(req.params.id);
    if (!group) return fail(res, 'Group not found.', 'NOT_FOUND', 404);

    const members = await Member.find({ group: group._id })
      .sort({ isLeader: -1, createdAt: 1 })
      .lean();
    const leader = members.find((m) => m.isLeader) || null;

    return ok(res, {
      group: {
        ...shapeGroup(group),
        leaderName: leader ? leader.name : null,
        leaderRegNo: leader ? leader.regNo : null,
      },
      members: members.map((m) => ({
        id: String(m._id),
        regNo: m.regNo,
        name: m.name,
        phone: m.phone,
        isLeader: Boolean(m.isLeader),
        role: m.isLeader ? 'GROUP LEADER' : 'MEMBER',
        createdAt: m.createdAt,
      })),
    });
  })
);

app.post(
  '/api/admin/groups',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const display = displayGroupName(req.body.name);
    const norm = normalizeGroupName(req.body.name);
    if (!isValidGroupName(norm)) {
      return fail(res, 'Please provide a valid group name.', 'INVALID_GROUP', 400);
    }
    const existing = await Group.findOne({ normalizedName: norm });
    if (existing) {
      return fail(res, 'A group with that name already exists.', 'DUPLICATE_GROUP', 409);
    }
    const group = await Group.create({
      name: display,
      normalizedName: norm,
      memberCount: 0,
    });
    console.log(`[admin] created group "${group.name}"`);
    sseBroadcast('group-created', { group: shapeGroup(group) });
    return ok(res, { message: 'Group created.', group: shapeGroup(group) }, 201);
  })
);

app.patch(
  '/api/admin/groups/:id',
  requireAdmin,
  asyncHandler(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return fail(res, 'Invalid group ID.', 'INVALID_ID', 400);
    }
    const group = await Group.findById(req.params.id);
    if (!group) return fail(res, 'Group not found.', 'NOT_FOUND', 404);

    const display = displayGroupName(req.body.name);
    const norm = normalizeGroupName(req.body.name);
    if (!isValidGroupName(norm)) {
      return fail(res, 'Please provide a valid group name.', 'INVALID_GROUP', 400);
    }

    const clash = await Group.findOne({ normalizedName: norm, _id: { $ne: group._id } });
    if (clash) {
      return fail(res, 'Another group already uses that name.', 'DUPLICATE_GROUP', 409);
    }

    const oldName = group.name;
    group.name = display;
    group.normalizedName = norm;
    await group.save();

    console.log(`[admin] renamed group "${oldName}" → "${display}"`);
    sseBroadcast('group-updated', { group: shapeGroup(group) });

    return ok(res, { message: 'Group renamed.', group: shapeGroup(group) });
  })
);

app.delete(
  '/api/admin/groups/:id',
  requireAdmin,
  asyncHandler(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return fail(res, 'Invalid group ID.', 'INVALID_ID', 400);
    }
    const group = await Group.findById(req.params.id);
    if (!group) return fail(res, 'Group not found.', 'NOT_FOUND', 404);

    const memberCount = await Member.countDocuments({ group: group._id });
    const confirm = String(req.query.confirm || '').toLowerCase() === 'true';

    if (memberCount > 0 && !confirm) {
      return fail(
        res,
        `This group contains ${memberCount} member(s). To delete the group and all of its members, resend with ?confirm=true.`,
        'CONFIRM_REQUIRED',
        409
      );
    }

    await Member.deleteMany({ group: group._id });
    await Group.deleteOne({ _id: group._id });

    console.log(`[admin] deleted group "${group.name}" (members=${memberCount})`);
    sseBroadcast('group-deleted', { groupId: String(group._id), name: group.name });

    return ok(res, {
      message: `Group and ${memberCount} member(s) deleted.`,
      deletedMembers: memberCount,
    });
  })
);

// ------------------- Admin: Members -------------------

app.post(
  '/api/admin/members',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const regNo = normalizeRegNo(req.body.regNo);
    const name = normalizeName(req.body.name);
    const phone = normalizePhone(req.body.phone);
    const groupId = req.body.groupId;

    if (!isValidRegNo(regNo)) return fail(res, 'Invalid registration number.', 'INVALID_REQNO', 400);
    if (!isValidName(name)) return fail(res, 'Invalid full name.', 'INVALID_NAME', 400);
    if (!phone) return fail(res, 'Invalid Kenyan phone number.', 'INVALID_PHONE', 400);
    if (!mongoose.isValidObjectId(groupId)) return fail(res, 'Invalid group.', 'INVALID_GROUP', 400);

    const group = await Group.findById(groupId);
    if (!group) return fail(res, 'Group not found.', 'NOT_FOUND', 404);

    const dupReg = await Member.findOne({ regNo });
    if (dupReg) {
      return fail(
        res,
        'This registration number has already been registered.',
        'DUPLICATE_REGNO',
        409
      );
    }

    // Atomic capacity increment.
    const incremented = await Group.findOneAndUpdate(
      { _id: group._id, memberCount: { $lt: CONFIG.MAX_GROUP_MEMBERS } },
      { $inc: { memberCount: 1 } },
      { new: true }
    );
    if (!incremented) {
      return fail(
        res,
        'This group is already full. Maximum is 10 members.',
        'GROUP_FULL',
        409
      );
    }

    const isLeader = incremented.memberCount === 1;
    let member;
    try {
      member = await Member.create({
        regNo,
        name,
        phone,
        group: group._id,
        isLeader,
      });
    } catch (err) {
      await Group.updateOne({ _id: group._id }, { $inc: { memberCount: -1 } });
      if (err && err.code === 11000 && err.keyPattern && err.keyPattern.regNo) {
        return fail(res, 'This registration number has already been registered.', 'DUPLICATE_REGNO', 409);
      }
      throw err;
    }

    if (isLeader) {
      await Group.updateOne({ _id: group._id, leader: null }, { $set: { leader: member._id } });
    }
    await reconcileGroupLeader(group._id);

    const freshGroup = await Group.findById(group._id);
    sseBroadcast('member-added', {
      member: shapeMember(member),
      group: shapeGroup(freshGroup),
    });

    return ok(res, { message: 'Member added.', member: shapeMember(member) }, 201);
  })
);

app.patch(
  '/api/admin/members/:id',
  requireAdmin,
  asyncHandler(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return fail(res, 'Invalid member ID.', 'INVALID_ID', 400);
    }
    const member = await Member.findById(req.params.id);
    if (!member) return fail(res, 'Member not found.', 'NOT_FOUND', 404);

    const oldGroupId = member.group;
    const newRegNo = req.body.regNo !== undefined ? normalizeRegNo(req.body.regNo) : member.regNo;
    const newName = req.body.name !== undefined ? normalizeName(req.body.name) : member.name;
    const newPhoneRaw = req.body.phone !== undefined ? req.body.phone : member.phone;
    const newPhone = normalizePhone(newPhoneRaw);
    const newGroupId = req.body.groupId !== undefined ? req.body.groupId : String(member.group);

    if (!isValidRegNo(newRegNo)) return fail(res, 'Invalid registration number.', 'INVALID_REQNO', 400);
    if (!isValidName(newName)) return fail(res, 'Invalid full name.', 'INVALID_NAME', 400);
    if (!newPhone) return fail(res, 'Invalid Kenyan phone number.', 'INVALID_PHONE', 400);
    if (!mongoose.isValidObjectId(newGroupId)) return fail(res, 'Invalid group.', 'INVALID_GROUP', 400);

    // Unique regNo (excluding self).
    const clash = await Member.findOne({ regNo: newRegNo, _id: { $ne: member._id } });
    if (clash) {
      return fail(res, 'Another member already uses this registration number.', 'DUPLICATE_REGNO', 409);
    }

    const movingGroup = String(newGroupId) !== String(oldGroupId);

    if (movingGroup) {
      const target = await Group.findById(newGroupId);
      if (!target) return fail(res, 'Target group not found.', 'NOT_FOUND', 404);

      // Atomic capacity increment on target.
      const incremented = await Group.findOneAndUpdate(
        { _id: target._id, memberCount: { $lt: CONFIG.MAX_GROUP_MEMBERS } },
        { $inc: { memberCount: 1 } },
        { new: true }
      );
      if (!incremented) {
        return fail(res, 'Target group is already full.', 'GROUP_FULL', 409);
      }

      // Move.
      member.regNo = newRegNo;
      member.name = newName;
      member.phone = newPhone;
      member.group = target._id;
      member.isLeader = false; // Demote; reconciliation will re-promote if target has no leader.
      await member.save();

      // Decrement old group.
      await Group.updateOne({ _id: oldGroupId }, { $inc: { memberCount: -1 } });

      // Reconcile both.
      await reconcileGroupLeader(oldGroupId);
      await reconcileGroupLeader(target._id);
    } else {
      member.regNo = newRegNo;
      member.name = newName;
      member.phone = newPhone;
      await member.save();
      await reconcileGroupLeader(member.group);
    }

    const freshGroup = await Group.findById(member.group);
    const freshMember = await Member.findById(member._id);

    sseBroadcast('member-updated', {
      member: shapeMember(freshMember),
      group: shapeGroup(freshGroup),
    });

    return ok(res, { message: 'Member updated.', member: shapeMember(freshMember) });
  })
);

app.delete(
  '/api/admin/members/:id',
  requireAdmin,
  asyncHandler(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return fail(res, 'Invalid member ID.', 'INVALID_ID', 400);
    }
    const member = await Member.findById(req.params.id);
    if (!member) return fail(res, 'Member not found.', 'NOT_FOUND', 404);

    const groupId = member.group;
    await Member.deleteOne({ _id: member._id });
    await Group.updateOne({ _id: groupId }, { $inc: { memberCount: -1 } });

    // If the deleted member was the leader, promote another.
    await reconcileGroupLeader(groupId);

    const freshGroup = await Group.findById(groupId);
    sseBroadcast('member-deleted', {
      memberId: String(member._id),
      group: freshGroup ? shapeGroup(freshGroup) : null,
    });

    console.log(`[admin] deleted member ${member.regNo} from group ${groupId}`);

    return ok(res, { message: 'Member deleted.' });
  })
);

// ============================================================================
// SECTION 11 — EXPORT
// ============================================================================

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const s = String(value);
  if (/[",\n\r]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

app.get(
  '/api/admin/export',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const members = await Member.find()
      .populate('group', 'name normalizedName')
      .sort({ 'group.name': 1, createdAt: 1 })
      .lean();

    // Sort by group name then createdAt in JS (Mongo can't sort across populate).
    members.sort((a, b) => {
      const ga = (a.group && a.group.name ? a.group.name : '').toLowerCase();
      const gb = (b.group && b.group.name ? b.group.name : '').toLowerCase();
      if (ga < gb) return -1;
      if (ga > gb) return 1;
      return new Date(a.createdAt) - new Date(b.createdAt);
    });

    const header = ['GROUP NAME', 'REG NO', 'NAME', 'PHONE NUMBER', 'ROLE', 'REGISTRATION DATE'];

    const lines = [header.join(',')];
    for (const m of members) {
      lines.push(
        [
          csvEscape(m.group ? m.group.name : ''),
          csvEscape(m.regNo),
          csvEscape(m.name),
          csvEscape(m.phone),
          csvEscape(m.isLeader ? 'GROUP LEADER' : 'MEMBER'),
          csvEscape(new Date(m.createdAt).toISOString()),
        ].join(',')
      );
    }

    const csv = lines.join('\r\n');
    const filename = `physics-education-groups-${new Date().toISOString().slice(0, 10)}.csv`;

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.status(200).send('\uFEFF' + csv); // BOM for Excel
  })
);

// ============================================================================
// SECTION 12 — SSE ENDPOINT
// ============================================================================

app.get(
  '/api/admin/events',
  requireAdmin,
  (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders && res.flushHeaders();

    res.write(`event: hello\ndata: ${JSON.stringify({ ts: Date.now() })}\n\n`);

    sseClients.add(res);

    req.on('close', () => {
      sseClients.delete(res);
      try {
        res.end();
      } catch (_) {
        /* ignore */
      }
    });
  }
);

// ============================================================================
// SECTION 13 — STATIC FILES + PAGE ROUTES
// ============================================================================

const publicDir = path.join(__dirname, 'public');

app.use(
  express.static(publicDir, {
    index: false,
    maxAge: IS_PROD ? '1h' : 0,
    setHeaders(res, filePath) {
      if (filePath.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-cache');
      }
    },
  })
);

app.get('/', (req, res) => res.sendFile(path.join(publicDir, 'index.html')));
app.get(
  ['/member', '/member-login', '/member-login.html', '/member-dashboard', '/member-dashboard.html'],
  (req, res) => res.sendFile(path.join(publicDir, 'member.html'))
);
app.get(
  ['/admin', '/admin-login', '/admin-login.html', '/admin-dashboard', '/admin-dashboard.html', '/admin-group'],
  (req, res) => res.sendFile(path.join(publicDir, 'admin.html'))
);

// ============================================================================
// SECTION 14 — 404 + ERROR HANDLERS
// ============================================================================

app.use('/api', (req, res) => {
  return fail(res, 'Endpoint not found.', 'NOT_FOUND', 404);
});

app.use((req, res) => {
  const notFoundPath = path.join(publicDir, '404.html');
  if (fs.existsSync(notFoundPath)) return res.status(404).sendFile(notFoundPath);
  return res.status(404).send('Not found');
});

// Centralized error handler — never leak internals.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  // Known app errors → safe to expose.
  if (err instanceof AppError) {
    console.warn(`[error] ${err.code}: ${err.message}`);
    return fail(res, err.message, err.code, err.status);
  }

  // Mongoose validation errors.
  if (err && err.name === 'ValidationError') {
    const first = Object.values(err.errors)[0];
    console.warn('[error] ValidationError:', first ? first.message : err.message);
    return fail(res, first ? first.message : 'Validation error.', 'VALIDATION', 400);
  }

  // Duplicate key.
  if (err && err.code === 11000) {
    console.warn('[error] Duplicate key:', JSON.stringify(err.keyPattern || {}));
    const keys = err.keyPattern || {};
    if (keys.regNo) return fail(res, 'This registration number already exists.', 'DUPLICATE_REGNO', 409);
    if (keys.deviceId) return fail(res, 'This device has already been used.', 'DEVICE_USED', 409);
    if (keys.normalizedName) return fail(res, 'A group with that name already exists.', 'DUPLICATE_GROUP', 409);
    return fail(res, 'Duplicate value.', 'DUPLICATE', 409);
  }

  // CastError (bad ObjectId, etc.).
  if (err && err.name === 'CastError') {
    return fail(res, 'Invalid identifier.', 'INVALID_ID', 400);
  }

  // Unknown error — log full stack on server, return generic message.
  console.error('[error] Unhandled:', err && err.stack ? err.stack : err);
  return fail(
    res,
    'We could not complete your request. Please contact the Administrator.',
    'SERVER_ERROR',
    500
  );
});

// ============================================================================
// SECTION 15 — SERVER STARTUP + SHUTDOWN
// ============================================================================

let httpServer = null;

async function start() {
  try {
    await connectDatabase();

    httpServer = http.createServer(app);

    httpServer.listen(PORT, '0.0.0.0', () => {
      console.log(`[boot] HTTP server listening on 0.0.0.0:${PORT}`);
      console.log(`[boot] Open http://localhost:${PORT}/ in your browser.`);
      console.log(`[boot] Admin bootstrap username: ${ADMIN_USERNAME}`);
    });

    httpServer.on('error', (err) => {
      console.error('[boot] HTTP server error:', err.message);
    });
  } catch (err) {
    console.error('[boot] Startup failed:', err.message);
    process.exit(1);
  }
}

async function shutdown(signal) {
  console.log(`\n[shutdown] Received ${signal}. Closing gracefully...`);
  try {
    if (httpServer) {
      await new Promise((resolve) => httpServer.close(resolve));
      console.log('[shutdown] HTTP server closed.');
    }
    for (const res of sseClients) {
      try { res.end(); } catch (_) {}
    }
    sseClients.clear();
    await disconnectDatabase();
  } catch (err) {
    console.error('[shutdown] Error during shutdown:', err.message);
  } finally {
    process.exit(0);
  }
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (reason) => {
  console.error('[process] Unhandled rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[process] Uncaught exception:', err && err.stack ? err.stack : err);
});

// Only auto-start when run directly (not when imported for tests).
if (require.main === module) {
  start();
}

module.exports = { app, start, CONFIG };
