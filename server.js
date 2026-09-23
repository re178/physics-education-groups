'use strict';

/**
 * ============================================================================
 * PHYSICS EDUCATION GROUPS — Complete Backend (server.js)
 * ============================================================================
 * Version: 1.4.0
 *
 * Highlights:
 *   - Registration open/close toggle
 *   - Payment-proof mode (M-Pesa) — toggleable by admin
 *   - Atomic group capacity enforcement (configurable cap 1–20)
 *   - Normalized group matching (case + whitespace insensitive)
 *   - Device lock + unique REG NO + leader reconciliation
 *   - Professional PDF export:
 *        /api/admin/export/pdf        → all groups + members (clean)
 *        /api/admin/export/paid/pdf   → paid members only (with payment info)
 *   - CSV export (clean columns)
 *   - Server-Sent Events for live admin updates
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
const PDFDocument = require('pdfkit');

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

  MAX_GROUP_MEMBERS_HARD_LIMIT: 20,
  MAX_GROUP_MEMBERS_DEFAULT: 10,

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
// SECTION 2 — UTILITIES
// ============================================================================

function normalizeGroupName(raw) {
  if (raw === null || raw === undefined) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

function displayGroupName(raw) {
  if (raw === null || raw === undefined) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function normalizeRegNo(raw) {
  if (raw === null || raw === undefined) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, '')
    .trim()
    .toUpperCase();
}

function normalizeName(raw) {
  if (raw === null || raw === undefined) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function normalizePhone(raw) {
  if (raw === null || raw === undefined) return null;
  let s = String(raw).replace(/[\s\-().]/g, '');
  if (s.startsWith('+')) s = s.slice(1);
  if (/^254(7|1)\d{8}$/.test(s)) return '+' + s;
  if (/^0(7|1)\d{8}$/.test(s)) return '+254' + s.slice(1);
  return null;
}

function normalizePochiPhone(raw) {
  return normalizePhone(raw);
}

function isValidDeviceId(id) {
  if (!id || typeof id !== 'string') return false;
  const trimmed = id.trim();
  if (trimmed.length < 8 || trimmed.length > 128) return false;
  return /^[A-Za-z0-9_\-:]+$/.test(trimmed);
}

function isValidGroupName(raw) {
  const n = normalizeGroupName(raw);
  if (!n) return false;
  if (n.length > 80) return false;
  return true;
}

function isValidRegNo(raw) {
  const n = normalizeRegNo(raw);
  if (n.length < 3 || n.length > 40) return false;
  return /^[A-Z0-9\-\/_.]+$/.test(n);
}

function isValidName(raw) {
  const n = normalizeName(raw);
  if (n.length < 2 || n.length > 120) return false;
  return /^[\p{L}\p{M}0-9 .,'\-()]+$/u.test(n);
}

function normalizeMpesaCode(raw) {
  if (raw === null || raw === undefined) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, '')
    .trim()
    .toUpperCase();
}

function isValidMpesaCode(raw) {
  const s = normalizeMpesaCode(raw);
  return /^[A-Z0-9]{10}$/.test(s);
}

function sanitizePaymentNote(raw) {
  if (raw === null || raw === undefined) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200);
}

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

function hashIp(ip) {
  if (!ip) return null;
  return crypto.createHmac('sha256', SESSION_SECRET).update(String(ip)).digest('hex');
}

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

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

class AppError extends Error {
  constructor(message, code = 'ERROR', status = 400) {
    super(message);
    this.code = code;
    this.status = status;
    this.expose = true;
  }
}

function ok(res, payload = {}, status = 200) {
  return res.status(status).json({ success: true, ...payload });
}

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
      max: [
        CONFIG.MAX_GROUP_MEMBERS_HARD_LIMIT,
        `Group cannot exceed ${CONFIG.MAX_GROUP_MEMBERS_HARD_LIMIT} members.`,
      ],
    },
  },
  { timestamps: true, versionKey: false }
);

GroupSchema.virtual('isFull').get(function () {
  return this.memberCount >= CONFIG.MAX_GROUP_MEMBERS_DEFAULT;
});
GroupSchema.virtual('availableSlots').get(function () {
  return Math.max(0, CONFIG.MAX_GROUP_MEMBERS_DEFAULT - this.memberCount);
});
GroupSchema.set('toJSON', { virtuals: true });
GroupSchema.set('toObject', { virtuals: true });

const Group = mongoose.model('Group', GroupSchema);

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

    // ---------- Lab manual payment fields (all optional) ----------
    mpesaCode: {
      type: String,
      default: null,
      trim: true,
      uppercase: true,
      maxlength: 20,
    },
    paymentAmount: {
      type: Number,
      default: null,
      min: 0,
    },
    paymentNote: {
      type: String,
      default: null,
      trim: true,
      maxlength: 200,
    },
    paymentSubmittedAt: {
      type: Date,
      default: null,
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
MemberSchema.index({ mpesaCode: 1 }, { sparse: true, name: 'mpesaCode_present' });

const Member = mongoose.model('Member', MemberSchema);

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

const SettingsSchema = new mongoose.Schema(
  {
    key: { type: String, required: true, unique: true, index: true, trim: true },
    value: { type: mongoose.Schema.Types.Mixed, default: null },
  },
  { timestamps: true, versionKey: false }
);

const Settings = mongoose.model('Settings', SettingsSchema);

// ============================================================================
// SECTION 5 — SETTINGS + BUSINESS HELPERS
// ============================================================================

async function getSetting(key, defaultValue = null) {
  try {
    const doc = await Settings.findOne({ key }).lean();
    return doc ? doc.value : defaultValue;
  } catch (_) {
    return defaultValue;
  }
}

async function setSetting(key, value) {
  const doc = await Settings.findOneAndUpdate(
    { key },
    { key, value },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  ).lean();
  return doc ? doc.value : value;
}

async function isRegistrationOpen() {
  const v = await getSetting('registration_open', true);
  return v !== false;
}

async function isPaymentProofRequired() {
  const v = await getSetting('require_payment_proof', false);
  return v === true;
}

async function getPaymentAmount() {
  const v = await getSetting('payment_amount', 45);
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : 45;
}

async function getPaymentPhone() {
  const v = await getSetting('payment_phone', '0741742291');
  const s = String(v || '').trim();
  return s || '0741742291';
}

async function getMaxGroupMembers() {
  const v = await getSetting('max_group_members', CONFIG.MAX_GROUP_MEMBERS_DEFAULT);
  const n = Number(v);
  if (!Number.isFinite(n)) return CONFIG.MAX_GROUP_MEMBERS_DEFAULT;
  return Math.max(1, Math.min(CONFIG.MAX_GROUP_MEMBERS_HARD_LIMIT, Math.floor(n)));
}

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

async function recalcMemberCount(groupId) {
  const count = await Member.countDocuments({ group: groupId });
  await Group.updateOne({ _id: groupId }, { $set: { memberCount: count } });
  return count;
}

function shapeGroup(group, extra = {}) {
  return {
    id: String(group._id),
    name: group.name,
    normalizedName: group.normalizedName,
    memberCount: group.memberCount,
    capacity: extra.capacity != null ? extra.capacity : CONFIG.MAX_GROUP_MEMBERS_DEFAULT,
    leader: group.leader ? String(group.leader) : null,
    createdAt: group.createdAt,
    updatedAt: group.updatedAt,
    ...extra,
  };
}

function shapeMember(member, opts = {}) {
  const base = {
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
  if (opts.includePayment) {
    base.mpesaCode = member.mpesaCode || null;
    base.paymentAmount = member.paymentAmount != null ? member.paymentAmount : null;
    base.paymentNote = member.paymentNote || null;
    base.paymentSubmittedAt = member.paymentSubmittedAt || null;
  }
  return base;
}

// ============================================================================
// SECTION 6 — SSE
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
app.set('trust proxy', 1);

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

app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true);
      if (CORS_ORIGIN.length === 0) return cb(null, false);
      return cb(null, CORS_ORIGIN.includes(origin));
    },
    credentials: true,
  })
);

app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(cookieParser());

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

const cookieOpts = (maxAgeMs) => ({
  httpOnly: true,
  secure: CONFIG.COOKIE_SECURE,
  sameSite: CONFIG.COOKIE_SAME_SITE,
  maxAge: maxAgeMs,
  path: '/',
});

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
    version: '1.4.0',
  });
});

app.get('/api/csrf-token', (req, res) => {
  const token = crypto.randomBytes(24).toString('hex');
  res.cookie(CONFIG.CSRF_COOKIE, token, {
    httpOnly: false,
    secure: CONFIG.COOKIE_SECURE,
    sameSite: CONFIG.COOKIE_SAME_SITE,
    maxAge: CONFIG.CSRF_TTL_MS,
    path: '/',
  });
  return ok(res, { token });
});

app.get(
  '/api/registration-status',
  asyncHandler(async (req, res) => {
    const open = await isRegistrationOpen();
    return ok(res, { open });
  })
);

/**
 * Public configuration needed by the register page.
 * Returns:
 *   - registrationOpen       : boolean
 *   - requirePaymentProof    : boolean — if true, the register page
 *                              must display the M-Pesa code field
 *   - paymentAmount          : number (KSH)
 *   - paymentPhone           : string (Pochi phone)
 *   - maxGroupMembers        : number
 */
app.get(
  '/api/payment-config',
  asyncHandler(async (req, res) => {
    const [
      registrationOpen,
      requirePaymentProof,
      paymentAmount,
      paymentPhone,
      maxGroupMembers,
    ] = await Promise.all([
      isRegistrationOpen(),
      isPaymentProofRequired(),
      getPaymentAmount(),
      getPaymentPhone(),
      getMaxGroupMembers(),
    ]);
    return ok(res, {
      registrationOpen,
      requirePaymentProof,
      paymentAmount,
      paymentPhone,
      maxGroupMembers,
    });
  })
);

app.post(
  '/api/register',
  registerLimiter,
  asyncHandler(async (req, res) => {
    // ---- Read current settings ----
    const [
      registrationOpen,
      requirePaymentProof,
      paymentAmount,
      paymentPhone,
      maxGroupMembers,
    ] = await Promise.all([
      isRegistrationOpen(),
      isPaymentProofRequired(),
      getPaymentAmount(),
      getPaymentPhone(),
      getMaxGroupMembers(),
    ]);

    if (!registrationOpen) {
      return fail(
        res,
        'Registration is currently closed. Please check back later or contact the Administrator.',
        'REGISTRATION_CLOSED',
        403
      );
    }

    // ---- Parse + normalize input ----
    const body = req.body || {};
    const regNo = normalizeRegNo(body.regNo);
    const name = normalizeName(body.name);
    const phoneRaw = body.phone;
    const groupDisplay = displayGroupName(body.groupName);
    const groupNorm = normalizeGroupName(body.groupName);
    const deviceId = typeof body.deviceId === 'string' ? body.deviceId.trim() : '';
    const deviceMetadata = sanitizeDeviceMetadata(body.deviceMetadata);
    const mpesaCode = normalizeMpesaCode(body.mpesaCode);
    const paymentNote = sanitizePaymentNote(body.paymentNote);

    // ---- Field validation ----
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

    // ---- Payment proof validation — only when the admin has switched it ON ----
    if (requirePaymentProof) {
      if (!isValidMpesaCode(mpesaCode)) {
        return fail(
          res,
          'Payment proof is required. Please send KSH ' +
            paymentAmount +
            ' to ' +
            paymentPhone +
            ' and paste the 10-character M-Pesa confirmation code.',
          'PAYMENT_REQUIRED',
          400
        );
      }
      if (!paymentNote) {
        return fail(
          res,
          'Please note down the time and day you paid in the payment note field.',
          'PAYMENT_NOTE_REQUIRED',
          400
        );
      }
    }

    // ---- Duplicate REG NO ----
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

    // ---- Device lock ----
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

    // ---- Find or create group (proper normalized matching) ----
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
          group = await Group.findOne({ normalizedName: groupNorm });
        } else {
          throw err;
        }
      }
    }

    if (!group) {
      return fail(res, 'We could not complete your registration. Please contact the Administrator.', 'GROUP_CREATE_FAILED', 500);
    }

    // ---- ATOMIC capacity increment (final authority) ----
    const incremented = await Group.findOneAndUpdate(
      { _id: group._id, memberCount: { $lt: maxGroupMembers } },
      { $inc: { memberCount: 1 } },
      { new: true }
    );

    if (!incremented) {
      console.log(`[register] group full: ${group.normalizedName} (cap=${maxGroupMembers})`);
      return fail(
        res,
        `This group is already full. A group can have a maximum of ${maxGroupMembers} members. Please contact the Administrator or choose another group.`,
        'GROUP_FULL',
        409
      );
    }

    const isLeader = incremented.memberCount === 1;

    // ---- Create member with rollback on failure ----
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
        mpesaCode: mpesaCode || null,
        paymentAmount: mpesaCode ? paymentAmount : null,
        paymentNote: paymentNote || null,
        paymentSubmittedAt: mpesaCode ? new Date() : null,
      });
    } catch (err) {
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

    if (isLeader) {
      await Group.updateOne({ _id: group._id, leader: null }, { $set: { leader: member._id } });
      await reconcileGroupLeader(group._id);
      console.log(`[register] leader assigned: ${regNo} → ${group.normalizedName}`);
    }

    const freshCount = await recalcMemberCount(group._id);

    const finalGroup = await Group.findById(group._id);
    sseBroadcast('registration', {
      member: shapeMember(member, { includePayment: true }),
      group: shapeGroup(finalGroup, { capacity: maxGroupMembers }),
      isNewGroup,
      isLeader,
    });

    console.log(
      `[register] success regNo=${regNo} group=${group.normalizedName} leader=${isLeader} paid=${Boolean(mpesaCode)}`
    );

    const message = isLeader
      ? 'You are the first member to register for this group. You have been assigned as the Group Leader.'
      : 'Registration successful.';

    return ok(
      res,
      {
        message,
        isLeader,
        isNewGroup,
        member: shapeMember(member, { includePayment: true }),
        group: shapeGroup(finalGroup, {
          capacity: maxGroupMembers,
          memberCount: freshCount,
        }),
        payment: {
          requirePaymentProof,
          paymentAmount,
          paymentPhone,
          mpesaCode: member.mpesaCode || null,
          paymentNote: member.paymentNote || null,
          paymentSubmittedAt: member.paymentSubmittedAt || null,
        },
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

    const maxGroupMembers = await getMaxGroupMembers();

    return ok(res, {
      message: 'Login successful.',
      member: shapeMember(member, { includePayment: true }),
      group: shapeGroup(group, { capacity: maxGroupMembers }),
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
    const maxGroupMembers = await getMaxGroupMembers();
    return ok(res, {
      member: shapeMember(member, { includePayment: true }),
      group: group ? shapeGroup(group, { capacity: maxGroupMembers }) : null,
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

    const [
      members,
      maxGroupMembers,
      requirePaymentProof,
      paymentAmount,
      paymentPhone,
    ] = await Promise.all([
      Member.find({ group: group._id })
        .sort({ isLeader: -1, createdAt: 1 })
        .select('regNo name phone isLeader group createdAt')
        .lean(),
      getMaxGroupMembers(),
      isPaymentProofRequired(),
      getPaymentAmount(),
      getPaymentPhone(),
    ]);

    const leader = members.find((m) => m.isLeader) || null;

    return ok(res, {
      group: {
        ...shapeGroup(group, { capacity: maxGroupMembers }),
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
      viewer: {
        regNo: member.regNo,
        name: member.name,
        isLeader: member.isLeader,
        mpesaCode: member.mpesaCode || null,
        paymentNote: member.paymentNote || null,
        paymentAmount: member.paymentAmount != null ? member.paymentAmount : null,
        paymentSubmittedAt: member.paymentSubmittedAt || null,
      },
      paymentConfig: {
        requirePaymentProof,
        paymentAmount,
        paymentPhone,
      },
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

    await Admin.updateOne(
      { _id: admin._id },
      { $set: { lastLoginAt: new Date() }, $inc: { loginCount: 1 } }
    );

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
  '/api/admin/registration-status',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const open = await isRegistrationOpen();
    return ok(res, { open });
  })
);

app.post(
  '/api/admin/registration-toggle',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const current = await isRegistrationOpen();
    const next = !current;
    await setSetting('registration_open', next);

    console.log(`[admin] registration submissions ${next ? 'OPENED' : 'CLOSED'}`);
    sseBroadcast('registration-status', { open: next });

    return ok(res, {
      open: next,
      message: next
        ? 'Student registration submissions are now OPEN.'
        : 'Student registration submissions are now CLOSED.',
    });
  })
);

app.get(
  '/api/admin/settings',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const [
      registrationOpen,
      requirePaymentProof,
      paymentAmount,
      paymentPhone,
      maxGroupMembers,
    ] = await Promise.all([
      isRegistrationOpen(),
      isPaymentProofRequired(),
      getPaymentAmount(),
      getPaymentPhone(),
      getMaxGroupMembers(),
    ]);

    return ok(res, {
      registrationOpen,
      requirePaymentProof,
      paymentAmount,
      paymentPhone,
      maxGroupMembers,
      maxGroupMembersHardLimit: CONFIG.MAX_GROUP_MEMBERS_HARD_LIMIT,
    });
  })
);

app.post(
  '/api/admin/settings',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const body = req.body || {};
    const updates = {};
    const errors = [];

    if (body.registrationOpen !== undefined) {
      updates.registration_open = body.registrationOpen === true;
    }

    if (body.requirePaymentProof !== undefined) {
      updates.require_payment_proof = body.requirePaymentProof === true;
    }

    if (body.paymentAmount !== undefined) {
      const n = Number(body.paymentAmount);
      if (!Number.isFinite(n) || n < 0 || n > 100000) {
        errors.push('Payment amount must be a number between 0 and 100000.');
      } else {
        updates.payment_amount = Math.round(n);
      }
    }

    if (body.paymentPhone !== undefined) {
      const p = normalizePochiPhone(body.paymentPhone);
      if (!p) {
        errors.push('Payment phone must be a valid Kenyan number (e.g. 0741742291).');
      } else {
        updates.payment_phone = p.startsWith('+254') ? '0' + p.slice(4) : p;
      }
    }

    if (body.maxGroupMembers !== undefined) {
      const n = Number(body.maxGroupMembers);
      if (!Number.isFinite(n) || n < 1 || n > CONFIG.MAX_GROUP_MEMBERS_HARD_LIMIT) {
        errors.push(
          `Max group members must be between 1 and ${CONFIG.MAX_GROUP_MEMBERS_HARD_LIMIT}.`
        );
      } else {
        updates.max_group_members = Math.floor(n);
      }
    }

    if (errors.length) {
      return fail(res, errors.join(' '), 'VALIDATION', 400);
    }

    const entries = Object.entries(updates);
    for (const [key, value] of entries) {
      await setSetting(key, value);
    }

    console.log(
      `[admin] settings updated: ${entries.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', ')}`
    );

    if (updates.registration_open !== undefined) {
      sseBroadcast('registration-status', { open: updates.registration_open });
    }
    sseBroadcast('settings-updated', { keys: entries.map(([k]) => k) });

    const [
      registrationOpen,
      requirePaymentProof,
      paymentAmount,
      paymentPhone,
      maxGroupMembers,
    ] = await Promise.all([
      isRegistrationOpen(),
      isPaymentProofRequired(),
      getPaymentAmount(),
      getPaymentPhone(),
      getMaxGroupMembers(),
    ]);

    return ok(res, {
      message: 'Settings saved.',
      registrationOpen,
      requirePaymentProof,
      paymentAmount,
      paymentPhone,
      maxGroupMembers,
      maxGroupMembersHardLimit: CONFIG.MAX_GROUP_MEMBERS_HARD_LIMIT,
    });
  })
);

/**
 * Paid/unpaid summary counts — used by an optional dashboard pill.
 */
app.get(
  '/api/admin/paid-summary',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const [total, paid] = await Promise.all([
      Member.countDocuments(),
      Member.countDocuments({ mpesaCode: { $type: 'string', $ne: '' } }),
    ]);
    return ok(res, { total, paid, unpaid: total - paid });
  })
);

app.get(
  '/api/admin/dashboard',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const [
      totalMembers,
      totalGroups,
      totalLeaders,
      maxGroupMembers,
      paidCount,
    ] = await Promise.all([
      Member.countDocuments(),
      Group.countDocuments(),
      Member.countDocuments({ isLeader: true }),
      getMaxGroupMembers(),
      Member.countDocuments({ mpesaCode: { $type: 'string', $ne: '' } }),
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
      totals: {
        totalMembers,
        totalGroups,
        totalLeaders,
        paid: paidCount,
        unpaid: totalMembers - paidCount,
      },
      maxGroupMembers,
      groups: groups.map((g) =>
        shapeGroup(g, {
          capacity: maxGroupMembers,
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
        mpesaCode: m.mpesaCode || null,
        paymentAmount: m.paymentAmount != null ? m.paymentAmount : null,
        paymentNote: m.paymentNote || null,
        paymentSubmittedAt: m.paymentSubmittedAt || null,
      })),
    });
  })
);

app.get(
  '/api/admin/groups',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const [groups, leaders, maxGroupMembers] = await Promise.all([
      Group.find().sort({ createdAt: 1 }).lean(),
      Member.find({ isLeader: true }).select('regNo name group').lean(),
      getMaxGroupMembers(),
    ]);
    const leaderByGroup = {};
    for (const l of leaders) leaderByGroup[String(l.group)] = { regNo: l.regNo, name: l.name };
    return ok(res, {
      groups: groups.map((g) =>
        shapeGroup(g, {
          capacity: maxGroupMembers,
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

    const [members, maxGroupMembers] = await Promise.all([
      Member.find({ group: group._id })
        .sort({ isLeader: -1, createdAt: 1 })
        .lean(),
      getMaxGroupMembers(),
    ]);
    const leader = members.find((m) => m.isLeader) || null;

    return ok(res, {
      group: {
        ...shapeGroup(group, { capacity: maxGroupMembers }),
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
        mpesaCode: m.mpesaCode || null,
        paymentAmount: m.paymentAmount != null ? m.paymentAmount : null,
        paymentNote: m.paymentNote || null,
        paymentSubmittedAt: m.paymentSubmittedAt || null,
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
    const maxGroupMembers = await getMaxGroupMembers();
    console.log(`[admin] created group "${group.name}"`);
    sseBroadcast('group-created', {
      group: shapeGroup(group, { capacity: maxGroupMembers }),
    });
    return ok(
      res,
      {
        message: 'Group created.',
        group: shapeGroup(group, { capacity: maxGroupMembers }),
      },
      201
    );
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

    const maxGroupMembers = await getMaxGroupMembers();
    console.log(`[admin] renamed group "${oldName}" → "${display}"`);
    sseBroadcast('group-updated', {
      group: shapeGroup(group, { capacity: maxGroupMembers }),
    });

    return ok(res, {
      message: 'Group renamed.',
      group: shapeGroup(group, { capacity: maxGroupMembers }),
    });
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

app.post(
  '/api/admin/members',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const regNo = normalizeRegNo(req.body.regNo);
    const name = normalizeName(req.body.name);
    const phone = normalizePhone(req.body.phone);
    const groupId = req.body.groupId;
    const mpesaCode = normalizeMpesaCode(req.body.mpesaCode);
    const paymentNote = sanitizePaymentNote(req.body.paymentNote);

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

    const maxGroupMembers = await getMaxGroupMembers();
    const paymentAmount = await getPaymentAmount();

    const incremented = await Group.findOneAndUpdate(
      { _id: group._id, memberCount: { $lt: maxGroupMembers } },
      { $inc: { memberCount: 1 } },
      { new: true }
    );
    if (!incremented) {
      return fail(
        res,
        `This group is already full. Maximum is ${maxGroupMembers} members.`,
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
        mpesaCode: mpesaCode || null,
        paymentAmount: mpesaCode ? paymentAmount : null,
        paymentNote: paymentNote || null,
        paymentSubmittedAt: mpesaCode ? new Date() : null,
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
      member: shapeMember(member, { includePayment: true }),
      group: shapeGroup(freshGroup, { capacity: maxGroupMembers }),
    });

    return ok(
      res,
      { message: 'Member added.', member: shapeMember(member, { includePayment: true }) },
      201
    );
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

    const clash = await Member.findOne({ regNo: newRegNo, _id: { $ne: member._id } });
    if (clash) {
      return fail(res, 'Another member already uses this registration number.', 'DUPLICATE_REGNO', 409);
    }

    const movingGroup = String(newGroupId) !== String(oldGroupId);
    const maxGroupMembers = await getMaxGroupMembers();

    if (movingGroup) {
      const target = await Group.findById(newGroupId);
      if (!target) return fail(res, 'Target group not found.', 'NOT_FOUND', 404);

      const incremented = await Group.findOneAndUpdate(
        { _id: target._id, memberCount: { $lt: maxGroupMembers } },
        { $inc: { memberCount: 1 } },
        { new: true }
      );
      if (!incremented) {
        return fail(res, 'Target group is already full.', 'GROUP_FULL', 409);
      }

      member.regNo = newRegNo;
      member.name = newName;
      member.phone = newPhone;
      member.group = target._id;
      member.isLeader = false;
      await member.save();

      await Group.updateOne({ _id: oldGroupId }, { $inc: { memberCount: -1 } });

      await reconcileGroupLeader(oldGroupId);
      await reconcileGroupLeader(target._id);
    } else {
      member.regNo = newRegNo;
      member.name = newName;
      member.phone = newPhone;
      await member.save();
      await reconcileGroupLeader(member.group);
    }

    if (req.body.mpesaCode !== undefined) {
      const code = normalizeMpesaCode(req.body.mpesaCode);
      member.mpesaCode = code || null;
      member.paymentSubmittedAt = code ? new Date() : null;
      if (code && member.paymentAmount == null) {
        member.paymentAmount = await getPaymentAmount();
      }
    }
    if (req.body.paymentNote !== undefined) {
      member.paymentNote = sanitizePaymentNote(req.body.paymentNote) || null;
    }
    await member.save();

    const freshGroup = await Group.findById(member.group);
    const freshMember = await Member.findById(member._id);

    sseBroadcast('member-updated', {
      member: shapeMember(freshMember, { includePayment: true }),
      group: shapeGroup(freshGroup, { capacity: maxGroupMembers }),
    });

    return ok(res, {
      message: 'Member updated.',
      member: shapeMember(freshMember, { includePayment: true }),
    });
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

    await reconcileGroupLeader(groupId);

    const freshGroup = await Group.findById(groupId);
    const maxGroupMembers = await getMaxGroupMembers();
    sseBroadcast('member-deleted', {
      memberId: String(member._id),
      group: freshGroup ? shapeGroup(freshGroup, { capacity: maxGroupMembers }) : null,
    });

    console.log(`[admin] deleted member ${member.regNo} from group ${groupId}`);

    return ok(res, { message: 'Member deleted.' });
  })
);

// ============================================================================
// SECTION 11 — CSV EXPORT (clean columns, no payment info)
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
    return res.status(200).send('\uFEFF' + csv);
  })
);

// ============================================================================
// SECTION 11B — PDF EXPORT
// ============================================================================

const PDF_COLORS = {
  textDark: '#111827',
  text: '#1f2937',
  textMuted: '#6b7280',
  border: '#d1d5db',
  borderLight: '#e5e7eb',
  bgSubtle: '#f9fafb',
  bgLight: '#f3f4f6',
  bgMedium: '#e5e7eb',
  white: '#ffffff',
  successText: '#15803d',
  dangerText: '#b91c1c',
};

const PDF_LAYOUT = Object.freeze({
  pageSize: 'A4',
  margin: 50,
  footerHeight: 40,
});

const A4_WIDTH = 595.28;
const A4_HEIGHT = 841.89;

function pdfFmtLong(d) {
  try {
    return new Date(d).toLocaleString('en-GB', {
      day: '2-digit', month: 'long', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch (_) { return ''; }
}

function pdfFmtShort(d) {
  try {
    return new Date(d).toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch (_) { return ''; }
}

/* ----------------------------------------------------------------
 * Shared header used by every PDF (banner + title + timestamp)
 * ---------------------------------------------------------------- */
function pdfDrawHeader(doc, { pageWidth, contentWidth, reportTitle }) {
  doc.save();
  doc.rect(0, 0, pageWidth, 3).fill(PDF_COLORS.textDark);
  doc.restore();

  doc.fillColor(PDF_COLORS.textDark).fontSize(18).font('Helvetica-Bold');
  doc.text('PHYSICS EDUCATION GROUPS', PDF_LAYOUT.margin, 26, {
    width: contentWidth,
    align: 'left',
    lineBreak: false,
  });

  doc.fontSize(9).font('Helvetica').fillColor(PDF_COLORS.textMuted);
  doc.text(String(reportTitle || '').toUpperCase(), PDF_LAYOUT.margin, 52, {
    width: contentWidth * 0.6,
    align: 'left',
    lineBreak: false,
  });

  doc.fontSize(8).font('Helvetica').fillColor(PDF_COLORS.textMuted);
  doc.text(
    'Generated: ' + pdfFmtLong(new Date()),
    PDF_LAYOUT.margin + contentWidth * 0.6,
    53,
    { width: contentWidth * 0.4, align: 'right', lineBreak: false }
  );

  doc.save();
  doc
    .moveTo(PDF_LAYOUT.margin, 74)
    .lineTo(pageWidth - PDF_LAYOUT.margin, 74)
    .strokeColor(PDF_COLORS.border)
    .lineWidth(0.5)
    .stroke();
  doc.restore();
}

function pdfDrawFooter(doc, { pageWidth, pageHeight, contentWidth }) {
  const range = doc.bufferedPageRange();
  const totalPages = range.count;
  const contentLeft = PDF_LAYOUT.margin;
  const contentRight = pageWidth - PDF_LAYOUT.margin;

  for (let i = 0; i < totalPages; i++) {
    doc.switchToPage(range.start + i);
    const footerY = pageHeight - 40;

    doc.save();
    doc
      .moveTo(contentLeft, footerY - 8)
      .lineTo(contentRight, footerY - 8)
      .strokeColor(PDF_COLORS.borderLight)
      .lineWidth(0.5)
      .stroke();
    doc.restore();

    doc.fontSize(7.5).font('Helvetica').fillColor(PDF_COLORS.textMuted);
    doc.text(
      'Physics Education Groups  •  Confidential administrative document',
      contentLeft,
      footerY,
      { width: contentWidth * 0.7, align: 'left', lineBreak: false }
    );
    doc.text(
      `Page ${i + 1} of ${totalPages}`,
      contentLeft + contentWidth * 0.7,
      footerY,
      { width: contentWidth * 0.3, align: 'right', lineBreak: false }
    );
  }
}

/* ----------------------------------------------------------------
 * PDF #1 — Full group registry (clean, no payment info)
 * ---------------------------------------------------------------- */
function buildGroupsPdf({ groups, reportTitle, reportSubtitle, maxGroupMembers }) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: PDF_LAYOUT.pageSize,
        margins: {
          top: PDF_LAYOUT.margin,
          bottom: PDF_LAYOUT.margin + 20,
          left: PDF_LAYOUT.margin,
          right: PDF_LAYOUT.margin,
        },
        bufferPages: true,
        autoFirstPage: false,
        info: {
          Title: reportTitle,
          Author: 'Physics Education Groups',
          Subject: 'Group Registry',
          Creator: 'Physics Education Groups',
        },
      });

      const chunks = [];
      doc.on('data', (c) => chunks.push(c));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', (err) => reject(err));

      doc.addPage();

      const pageWidth = (doc.page && doc.page.width) || A4_WIDTH;
      const pageHeight = (doc.page && doc.page.height) || A4_HEIGHT;
      const contentWidth = pageWidth - PDF_LAYOUT.margin * 2;
      const contentLeft = PDF_LAYOUT.margin;
      const contentRight = pageWidth - PDF_LAYOUT.margin;
      const capacity = maxGroupMembers || CONFIG.MAX_GROUP_MEMBERS_DEFAULT;

      const totals = groups.reduce(
        (acc, g) => {
          acc.groups += 1;
          acc.members += (g.members || []).length;
          acc.leaders += (g.members || []).filter((m) => m.isLeader).length;
          return acc;
        },
        { groups: 0, members: 0, leaders: 0 }
      );

      const rawCols = { idx: 28, regNo: 90, name: 165, phone: 100, role: 112 };
      const totalRaw = rawCols.idx + rawCols.regNo + rawCols.name + rawCols.phone + rawCols.role;
      const scale = contentWidth / totalRaw;
      const colWidths = {
        idx: rawCols.idx * scale,
        regNo: rawCols.regNo * scale,
        name: rawCols.name * scale,
        phone: rawCols.phone * scale,
        role: rawCols.role * scale,
      };
      const colX = {
        idx: contentLeft,
        regNo: contentLeft + colWidths.idx,
        name: contentLeft + colWidths.idx + colWidths.regNo,
        phone: contentLeft + colWidths.idx + colWidths.regNo + colWidths.name,
        role:
          contentLeft +
          colWidths.idx +
          colWidths.regNo +
          colWidths.name +
          colWidths.phone,
      };

      pdfDrawHeader(doc, { pageWidth, contentWidth, reportTitle });

      let y = 92;

      if (reportSubtitle) {
        doc.fontSize(10).font('Helvetica-Oblique').fillColor(PDF_COLORS.textMuted);
        doc.text(reportSubtitle, contentLeft, y, { width: contentWidth, align: 'left' });
        y += 16;
      }

      const summaryBoxHeight = 62;
      doc.save();
      doc
        .roundedRect(contentLeft, y, contentWidth, summaryBoxHeight, 4)
        .fillAndStroke(PDF_COLORS.bgSubtle, PDF_COLORS.border);
      doc.restore();

      const summaryItems = [
        { label: 'TOTAL GROUPS', value: String(totals.groups) },
        { label: 'TOTAL MEMBERS', value: String(totals.members) },
        { label: 'GROUP LEADERS', value: String(totals.leaders) },
        { label: 'CAPACITY PER GROUP', value: String(capacity) },
      ];
      const itemWidth = contentWidth / summaryItems.length;
      summaryItems.forEach((item, i) => {
        const ix = contentLeft + i * itemWidth + 14;
        doc.fontSize(7.5).font('Helvetica-Bold').fillColor(PDF_COLORS.textMuted);
        doc.text(item.label, ix, y + 12, { width: itemWidth - 20, align: 'left' });
        doc.fontSize(17).font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(item.value, ix, y + 26, { width: itemWidth - 20, align: 'left' });
      });

      y += summaryBoxHeight + 22;

      function ensureSpace(needed) {
        if (y + needed > pageHeight - PDF_LAYOUT.margin - PDF_LAYOUT.footerHeight + 10) {
          doc.addPage();
          pdfDrawHeader(doc, { pageWidth, contentWidth, reportTitle });
          y = 92;
        }
      }

      function drawGroupHeader(group, index) {
        ensureSpace(80);

        const headerHeight = 44;
        doc.save();
        doc
          .roundedRect(contentLeft, y, contentWidth, headerHeight, 4)
          .fillAndStroke(PDF_COLORS.bgLight, PDF_COLORS.border);
        doc.restore();

        doc.save();
        doc
          .circle(contentLeft + 24, y + headerHeight / 2, 13)
          .fillAndStroke(PDF_COLORS.white, PDF_COLORS.textDark);
        doc.restore();
        doc.fontSize(11).font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(String(index), contentLeft + 18, y + headerHeight / 2 - 6, {
          width: 12,
          align: 'center',
        });

        doc.fontSize(13).font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(group.name, contentLeft + 48, y + 8, {
          width: contentWidth - 200,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        doc.fontSize(8.5).font('Helvetica').fillColor(PDF_COLORS.textMuted);
        const metaParts = [];
        metaParts.push(`${(group.members || []).length} / ${capacity} members`);
        if (group.leaderName) {
          metaParts.push(
            `Leader: ${group.leaderName}${group.leaderRegNo ? ' (' + group.leaderRegNo + ')' : ''}`
          );
        }
        doc.text(metaParts.join('   •   '), contentLeft + 48, y + 26, {
          width: contentWidth - 60,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        const isFull = (group.members || []).length >= capacity;
        const badgeText = isFull ? 'FULL' : 'OPEN';
        const badgeColor = isFull ? PDF_COLORS.dangerText : PDF_COLORS.successText;
        const badgeWidth = 44;
        const badgeX = contentRight - badgeWidth - 12;
        doc.save();
        doc
          .roundedRect(badgeX, y + 13, badgeWidth, 18, 9)
          .fillAndStroke(PDF_COLORS.white, badgeColor);
        doc.restore();
        doc.fontSize(8).font('Helvetica-Bold').fillColor(badgeColor);
        doc.text(badgeText, badgeX, y + 18, { width: badgeWidth, align: 'center' });

        y += headerHeight + 8;

        doc.save();
        doc.rect(contentLeft, y, contentWidth, 22).fill(PDF_COLORS.bgMedium);
        doc.restore();

        const headerY = y + 7;
        doc.fontSize(8).font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text('#', colX.idx + 4, headerY, { width: colWidths.idx - 8, align: 'left', lineBreak: false });
        doc.text('REG NO', colX.regNo + 6, headerY, { width: colWidths.regNo - 8, align: 'left', lineBreak: false });
        doc.text('NAME', colX.name + 6, headerY, { width: colWidths.name - 8, align: 'left', lineBreak: false });
        doc.text('PHONE NUMBER', colX.phone + 6, headerY, { width: colWidths.phone - 8, align: 'left', lineBreak: false });
        doc.text('ROLE', colX.role + 6, headerY, { width: colWidths.role - 8, align: 'left', lineBreak: false });

        y += 22;
      }

      function drawMemberRow(m, idx, isLeader) {
        const rowHeight = 22;
        ensureSpace(rowHeight + 2);

        if (isLeader) {
          doc.save();
          doc.rect(contentLeft, y, contentWidth, rowHeight).fill(PDF_COLORS.bgLight);
          doc.restore();
          doc.save();
          doc.rect(contentLeft, y, 2, rowHeight).fill(PDF_COLORS.textDark);
          doc.restore();
        } else if (idx % 2 === 1) {
          doc.save();
          doc.rect(contentLeft, y, contentWidth, rowHeight).fill(PDF_COLORS.bgSubtle);
          doc.restore();
        }

        const cellY = y + 7;

        doc.fontSize(9).font('Helvetica').fillColor(PDF_COLORS.text);
        doc.text(String(idx), colX.idx + 4, cellY, {
          width: colWidths.idx - 8,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        doc.font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(m.regNo || '', colX.regNo + 6, cellY, {
          width: colWidths.regNo - 8,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        doc.font(isLeader ? 'Helvetica-Bold' : 'Helvetica').fillColor(PDF_COLORS.text);
        doc.text(m.name || '', colX.name + 6, cellY, {
          width: colWidths.name - 8,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        doc.font('Helvetica').fillColor(PDF_COLORS.textMuted);
        doc.text(m.phone || '', colX.phone + 6, cellY, {
          width: colWidths.phone - 8,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        if (isLeader) {
          doc.font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
          doc.text('GROUP LEADER', colX.role + 6, cellY, {
            width: colWidths.role - 8,
            align: 'left',
            lineBreak: false,
            ellipsis: true,
          });
        } else {
          doc.font('Helvetica').fillColor(PDF_COLORS.textMuted);
          doc.text('MEMBER', colX.role + 6, cellY, {
            width: colWidths.role - 8,
            align: 'left',
            lineBreak: false,
            ellipsis: true,
          });
        }

        doc.save();
        doc
          .moveTo(contentLeft, y + rowHeight)
          .lineTo(contentRight, y + rowHeight)
          .strokeColor(PDF_COLORS.borderLight)
          .lineWidth(0.4)
          .stroke();
        doc.restore();

        y += rowHeight;
      }

      if (groups.length === 0) {
        doc.fontSize(11).font('Helvetica-Oblique').fillColor(PDF_COLORS.textMuted);
        doc.text('No groups have been registered yet.', contentLeft, y + 20, {
          width: contentWidth,
          align: 'center',
        });
      } else {
        groups.forEach((group, gi) => {
          drawGroupHeader(group, gi + 1);

          const members = group.members || [];
          if (members.length === 0) {
            const emptyHeight = 26;
            doc.save();
            doc
              .rect(contentLeft, y, contentWidth, emptyHeight)
              .fillAndStroke(PDF_COLORS.bgSubtle, PDF_COLORS.border);
            doc.restore();
            doc.fontSize(9).font('Helvetica-Oblique').fillColor(PDF_COLORS.textMuted);
            doc.text('No members in this group yet.', contentLeft + 8, y + 8, {
              width: contentWidth - 16,
              align: 'left',
            });
            y += emptyHeight;
          } else {
            members.forEach((m, mi) => {
              drawMemberRow(m, mi + 1, Boolean(m.isLeader));
            });
          }

          y += 18;
        });
      }

      pdfDrawFooter(doc, { pageWidth, pageHeight, contentWidth });
      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

/* ----------------------------------------------------------------
 * PDF #2 — Paid members only (reconciliation document)
 * ---------------------------------------------------------------- */
function buildPaidMembersPdf({ rows, reportTitle, reportSubtitle }) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: PDF_LAYOUT.pageSize,
        margins: {
          top: PDF_LAYOUT.margin,
          bottom: PDF_LAYOUT.margin + 20,
          left: PDF_LAYOUT.margin,
          right: PDF_LAYOUT.margin,
        },
        bufferPages: true,
        autoFirstPage: false,
        info: {
          Title: reportTitle,
          Author: 'Physics Education Groups',
          Subject: 'Paid Members',
          Creator: 'Physics Education Groups',
        },
      });

      const chunks = [];
      doc.on('data', (c) => chunks.push(c));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', (err) => reject(err));

      doc.addPage();

      const pageWidth = (doc.page && doc.page.width) || A4_WIDTH;
      const pageHeight = (doc.page && doc.page.height) || A4_HEIGHT;
      const contentWidth = pageWidth - PDF_LAYOUT.margin * 2;
      const contentLeft = PDF_LAYOUT.margin;
      const contentRight = pageWidth - PDF_LAYOUT.margin;

      const totals = {
        count: rows.length,
        totalAmount: rows.reduce((a, r) => a + (Number(r.paymentAmount) || 0), 0),
        groups: new Set(rows.map((r) => r.groupName)).size,
      };

      // Column layout: # / Group / RegNo / Name / Phone / M-Pesa / Amount / Note / Paid At
      const rawCols = {
        idx: 22,
        group: 92,
        regNo: 66,
        name: 100,
        phone: 66,
        mpesa: 60,
        amount: 40,
        note: 80,
        paidAt: 72,
      };
      const totalRaw = Object.values(rawCols).reduce((a, b) => a + b, 0);
      const scale = contentWidth / totalRaw;
      const colWidths = {};
      let accum = 0;
      const colX = {};
      for (const [key, w] of Object.entries(rawCols)) {
        colX[key] = contentLeft + accum * scale;
        colWidths[key] = w * scale;
        accum += w;
      }

      pdfDrawHeader(doc, { pageWidth, contentWidth, reportTitle });

      let y = 92;

      if (reportSubtitle) {
        doc.fontSize(10).font('Helvetica-Oblique').fillColor(PDF_COLORS.textMuted);
        doc.text(reportSubtitle, contentLeft, y, { width: contentWidth, align: 'left' });
        y += 16;
      }

      const summaryBoxHeight = 62;
      doc.save();
      doc
        .roundedRect(contentLeft, y, contentWidth, summaryBoxHeight, 4)
        .fillAndStroke(PDF_COLORS.bgSubtle, PDF_COLORS.border);
      doc.restore();

      const summaryItems = [
        { label: 'PAID MEMBERS', value: String(totals.count) },
        { label: 'GROUPS WITH PAYMENTS', value: String(totals.groups) },
        { label: 'TOTAL AMOUNT (KSH)', value: String(totals.totalAmount) },
        { label: 'REPORT TYPE', value: 'PAID' },
      ];
      const itemWidth = contentWidth / summaryItems.length;
      summaryItems.forEach((item, i) => {
        const ix = contentLeft + i * itemWidth + 14;
        doc.fontSize(7.5).font('Helvetica-Bold').fillColor(PDF_COLORS.textMuted);
        doc.text(item.label, ix, y + 12, { width: itemWidth - 20, align: 'left' });
        doc.fontSize(17).font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(item.value, ix, y + 26, { width: itemWidth - 20, align: 'left' });
      });

      y += summaryBoxHeight + 22;

      function ensureSpace(needed) {
        if (y + needed > pageHeight - PDF_LAYOUT.margin - PDF_LAYOUT.footerHeight + 10) {
          doc.addPage();
          pdfDrawHeader(doc, { pageWidth, contentWidth, reportTitle });
          y = 92;
        }
      }

      // Table header
      ensureSpace(40);
      doc.save();
      doc.rect(contentLeft, y, contentWidth, 22).fill(PDF_COLORS.bgMedium);
      doc.restore();

      const headerY = y + 7;
      doc.fontSize(7.5).font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
      doc.text('#', colX.idx + 3, headerY, { width: colWidths.idx - 6, align: 'left', lineBreak: false });
      doc.text('GROUP', colX.group + 4, headerY, { width: colWidths.group - 8, align: 'left', lineBreak: false });
      doc.text('REG NO', colX.regNo + 4, headerY, { width: colWidths.regNo - 8, align: 'left', lineBreak: false });
      doc.text('NAME', colX.name + 4, headerY, { width: colWidths.name - 8, align: 'left', lineBreak: false });
      doc.text('PHONE', colX.phone + 4, headerY, { width: colWidths.phone - 8, align: 'left', lineBreak: false });
      doc.text('M-PESA', colX.mpesa + 4, headerY, { width: colWidths.mpesa - 8, align: 'left', lineBreak: false });
      doc.text('KSH', colX.amount + 4, headerY, { width: colWidths.amount - 8, align: 'left', lineBreak: false });
      doc.text('NOTE', colX.note + 4, headerY, { width: colWidths.note - 8, align: 'left', lineBreak: false });
      doc.text('PAID AT', colX.paidAt + 4, headerY, { width: colWidths.paidAt - 8, align: 'left', lineBreak: false });
      y += 22;

      function drawRow(r, idx) {
        const rowHeight = 24;
        ensureSpace(rowHeight + 2);

        if (idx % 2 === 1) {
          doc.save();
          doc.rect(contentLeft, y, contentWidth, rowHeight).fill(PDF_COLORS.bgSubtle);
          doc.restore();
        }

        const cellY = y + 8;
        doc.fontSize(8).font('Helvetica').fillColor(PDF_COLORS.text);

        doc.text(String(idx), colX.idx + 3, cellY, {
          width: colWidths.idx - 6,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        doc.text(r.groupName || '', colX.group + 4, cellY, {
          width: colWidths.group - 8,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        doc.font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(r.regNo || '', colX.regNo + 4, cellY, {
          width: colWidths.regNo - 8,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        doc.font('Helvetica').fillColor(PDF_COLORS.text);
        doc.text(r.name || '', colX.name + 4, cellY, {
          width: colWidths.name - 8,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        doc.fillColor(PDF_COLORS.textMuted);
        doc.text(r.phone || '', colX.phone + 4, cellY, {
          width: colWidths.phone - 8,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        doc.font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(r.mpesaCode || '', colX.mpesa + 4, cellY, {
          width: colWidths.mpesa - 8,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        doc.font('Helvetica').fillColor(PDF_COLORS.text);
        doc.text(r.paymentAmount != null ? String(r.paymentAmount) : '', colX.amount + 4, cellY, {
          width: colWidths.amount - 8,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        doc.fillColor(PDF_COLORS.textMuted);
        doc.text(r.paymentNote || '', colX.note + 4, cellY, {
          width: colWidths.note - 8,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        doc.fontSize(7.5).fillColor(PDF_COLORS.textMuted);
        doc.text(r.paymentSubmittedAt ? pdfFmtShort(r.paymentSubmittedAt) : '', colX.paidAt + 4, cellY + 1, {
          width: colWidths.paidAt - 8,
          align: 'left',
          lineBreak: false,
          ellipsis: true,
        });

        doc.save();
        doc
          .moveTo(contentLeft, y + rowHeight)
          .lineTo(contentRight, y + rowHeight)
          .strokeColor(PDF_COLORS.borderLight)
          .lineWidth(0.4)
          .stroke();
        doc.restore();

        y += rowHeight;
      }

      if (rows.length === 0) {
        doc.fontSize(11).font('Helvetica-Oblique').fillColor(PDF_COLORS.textMuted);
        doc.text('No paid members have been recorded yet.', contentLeft, y + 20, {
          width: contentWidth,
          align: 'center',
        });
      } else {
        rows.forEach((r, i) => drawRow(r, i + 1));

        // Bottom summary line
        y += 12;
        ensureSpace(30);
        doc.save();
        doc
          .moveTo(contentLeft, y)
          .lineTo(contentRight, y)
          .strokeColor(PDF_COLORS.border)
          .lineWidth(0.7)
          .stroke();
        doc.restore();
        doc.fontSize(10).font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(
          `Total paid: ${totals.count} member(s)  •  Total collected: KSH ${totals.totalAmount}`,
          contentLeft,
          y + 8,
          { width: contentWidth, align: 'right' }
        );
      }

      pdfDrawFooter(doc, { pageWidth, pageHeight, contentWidth });
      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

// ---------- Admin PDF: all groups (clean, no payment info) ----------
app.get(
  '/api/admin/export/pdf',
  requireAdmin,
  asyncHandler(async (req, res) => {
    try {
      const groups = await Group.find().lean();

      const allLeaders = await Member.find({ isLeader: true })
        .select('regNo name group')
        .lean();
      const leadersByGroup = {};
      for (const l of allLeaders) {
        leadersByGroup[String(l.group)] = { regNo: l.regNo, name: l.name };
      }

      groups.sort((a, b) =>
        String(a.name || '').toLowerCase().localeCompare(String(b.name || '').toLowerCase())
      );

      const maxGroupMembers = await getMaxGroupMembers();

      const groupsWithMembers = [];
      for (const g of groups) {
        const members = await Member.find({ group: g._id })
          .sort({ isLeader: -1, createdAt: 1, _id: 1 })
          .select('regNo name phone isLeader createdAt')
          .lean();
        const leader = leadersByGroup[String(g._id)] || null;
        groupsWithMembers.push({
          id: String(g._id),
          name: g.name,
          memberCount: g.memberCount,
          capacity: maxGroupMembers,
          leaderName: leader ? leader.name : null,
          leaderRegNo: leader ? leader.regNo : null,
          members: members.map((m) => ({
            regNo: m.regNo,
            name: m.name,
            phone: m.phone,
            isLeader: Boolean(m.isLeader),
            createdAt: m.createdAt,
          })),
        });
      }

      const pdfBuffer = await buildGroupsPdf({
        groups: groupsWithMembers,
        reportTitle: 'Complete Group Registry',
        reportSubtitle: `All Physics Education groups and their members (${groupsWithMembers.length} group${
          groupsWithMembers.length === 1 ? '' : 's'
        }).`,
        maxGroupMembers,
      });

      const filename = `physics-education-groups-complete-${new Date()
        .toISOString()
        .slice(0, 10)}.pdf`;

      console.log(
        `[admin] PDF export generated (${groupsWithMembers.length} groups, ${pdfBuffer.length} bytes)`
      );

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Length', String(pdfBuffer.length));
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).end(pdfBuffer);
    } catch (pdfErr) {
      console.error('[admin-pdf] ERROR:', pdfErr && pdfErr.stack ? pdfErr.stack : pdfErr);
      throw pdfErr;
    }
  })
);

// ---------- Admin PDF: PAID members only ----------
app.get(
  '/api/admin/export/paid/pdf',
  requireAdmin,
  asyncHandler(async (req, res) => {
    try {
      const paidMembers = await Member.find({
        mpesaCode: { $type: 'string', $ne: '' },
      })
        .populate('group', 'name normalizedName')
        .lean();

      // Sort by group name, then payment date (earliest first)
      paidMembers.sort((a, b) => {
        const ga = (a.group && a.group.name ? a.group.name : '').toLowerCase();
        const gb = (b.group && b.group.name ? b.group.name : '').toLowerCase();
        if (ga < gb) return -1;
        if (ga > gb) return 1;
        const pa = a.paymentSubmittedAt ? new Date(a.paymentSubmittedAt).getTime() : 0;
        const pb = b.paymentSubmittedAt ? new Date(b.paymentSubmittedAt).getTime() : 0;
        if (pa !== pb) return pa - pb;
        return String(a.regNo).localeCompare(String(b.regNo));
      });

      const rows = paidMembers.map((m) => ({
        groupName: m.group ? m.group.name : '',
        regNo: m.regNo,
        name: m.name,
        phone: m.phone,
        mpesaCode: m.mpesaCode || '',
        paymentAmount: m.paymentAmount != null ? m.paymentAmount : null,
        paymentNote: m.paymentNote || '',
        paymentSubmittedAt: m.paymentSubmittedAt || null,
        isLeader: Boolean(m.isLeader),
      }));

      const pdfBuffer = await buildPaidMembersPdf({
        rows,
        reportTitle: 'Paid Members — Reconciliation Report',
        reportSubtitle: `Only members who have submitted an M-Pesa confirmation code (${rows.length} record${
          rows.length === 1 ? '' : 's'
        }).`,
      });

      const filename = `physics-education-groups-paid-${new Date()
        .toISOString()
        .slice(0, 10)}.pdf`;

      console.log(
        `[admin] PAID PDF export generated (${rows.length} paid members, ${pdfBuffer.length} bytes)`
      );

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Length', String(pdfBuffer.length));
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).end(pdfBuffer);
    } catch (pdfErr) {
      console.error('[admin-paid-pdf] ERROR:', pdfErr && pdfErr.stack ? pdfErr.stack : pdfErr);
      throw pdfErr;
    }
  })
);

// ---------- Member PDF: own group only ----------
app.get(
  '/api/member/export/pdf',
  requireMember,
  asyncHandler(async (req, res) => {
    try {
      const member = await Member.findById(req._session.subjectId);
      if (!member) {
        return fail(res, 'Session invalid.', 'SESSION_INVALID', 401);
      }
      const group = await Group.findById(member.group);
      if (!group) {
        return fail(res, 'Group not found.', 'NOT_FOUND', 404);
      }

      const [members, maxGroupMembers] = await Promise.all([
        Member.find({ group: group._id })
          .sort({ isLeader: -1, createdAt: 1, _id: 1 })
          .select('regNo name phone isLeader createdAt')
          .lean(),
        getMaxGroupMembers(),
      ]);

      const leader = members.find((m) => m.isLeader) || null;

      const pdfBuffer = await buildGroupsPdf({
        groups: [
          {
            id: String(group._id),
            name: group.name,
            memberCount: group.memberCount,
            capacity: maxGroupMembers,
            leaderName: leader ? leader.name : null,
            leaderRegNo: leader ? leader.regNo : null,
            members: members.map((m) => ({
              regNo: m.regNo,
              name: m.name,
              phone: m.phone,
              isLeader: Boolean(m.isLeader),
              createdAt: m.createdAt,
            })),
          },
        ],
        reportTitle: 'Group Member Directory',
        reportSubtitle: `Group roster for "${group.name}".`,
        maxGroupMembers,
      });

      const safeName =
        group.name.replace(/[^A-Za-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '') || 'group';
      const filename = `physics-group-${safeName}-${new Date().toISOString().slice(0, 10)}.pdf`;

      console.log(`[member] PDF export generated for group "${group.name}" (${pdfBuffer.length} bytes)`);

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Length', String(pdfBuffer.length));
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).end(pdfBuffer);
    } catch (pdfErr) {
      console.error('[member-pdf] ERROR:', pdfErr && pdfErr.stack ? pdfErr.stack : pdfErr);
      throw pdfErr;
    }
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

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  if (err instanceof AppError) {
    console.warn(`[error] ${err.code}: ${err.message}`);
    return fail(res, err.message, err.code, err.status);
  }

  if (err && err.name === 'ValidationError') {
    const first = Object.values(err.errors)[0];
    console.warn('[error] ValidationError:', first ? first.message : err.message);
    return fail(res, first ? first.message : 'Validation error.', 'VALIDATION', 400);
  }

  if (err && err.code === 11000) {
    console.warn('[error] Duplicate key:', JSON.stringify(err.keyPattern || {}));
    const keys = err.keyPattern || {};
    if (keys.regNo) return fail(res, 'This registration number already exists.', 'DUPLICATE_REGNO', 409);
    if (keys.deviceId) return fail(res, 'This device has already been used.', 'DEVICE_USED', 409);
    if (keys.normalizedName) return fail(res, 'A group with that name already exists.', 'DUPLICATE_GROUP', 409);
    return fail(res, 'Duplicate value.', 'DUPLICATE', 409);
  }

  if (err && err.name === 'CastError') {
    return fail(res, 'Invalid identifier.', 'INVALID_ID', 400);
  }

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

if (require.main === module) {
  start();
}

module.exports = { app, start, CONFIG };
