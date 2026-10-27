require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const { SUPABASE_URL, SUPABASE_SERVICE_KEY, JWT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD } = process.env;
if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !JWT_SECRET) {
  console.error('Missing env: SUPABASE_URL, SUPABASE_SERVICE_KEY and JWT_SECRET are required.');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '10mb' })); // images frontend me compress hoti hain
app.use(express.static(path.join(__dirname, 'public')));

// ---------- helpers ----------
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const fail = (res, code, msg) => res.status(code).json({ error: msg });
const STATUSES = ['Processing', 'Shipped', 'Delivered', 'Cancelled'];

const publicUser = (u) => ({
  username: u.username, full_name: u.full_name, mobile: u.mobile, location: u.location,
  house_number: u.house_number, pincode: u.pincode, profile_photo: u.profile_photo
});
const signToken = (u, expiresIn) =>
  jwt.sign({ id: u.id, username: u.username, role: u.role }, JWT_SECRET, { expiresIn });

async function getSetting(key, fallback) {
  const { data, error } = await supabase.from('store_settings').select('value').eq('key', key).maybeSingle();
  if (error) throw error;
  return data ? data.value : fallback;
}

async function adjustStock(id, delta) {
  const { data, error } = await supabase.rpc('adjust_stock', { p_id: id, p_delta: delta });
  if (error) throw error;
  return data === true;
}
async function restoreStock(items) {
  for (const it of items || []) {
    try { await adjustStock(Number(it.id), Number(it.qty)); }
    catch (e) { console.error('Stock restore failed', it, e.message); }
  }
}

// ---------- middleware ----------
const authenticate = (req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return fail(res, 401, 'Please login first');
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return fail(res, 401, 'Session expired. Please login again.');
    req.user = user;
    next();
  });
};
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return fail(res, 403, 'Admin access required');
  next();
};
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in a few minutes.' }
});

app.get('/health', (req, res) => res.json({ ok: true }));

// ---------- auth ----------
app.post('/api/auth/login', loginLimiter, wrap(async (req, res) => {
  const username = String((req.body || {}).username || '').trim();
  const password = String((req.body || {}).password || '');
  if (username.length < 3 || username.length > 30) return fail(res, 400, 'Username must be 3-30 characters');
  if (password.length < 4 || password.length > 100) return fail(res, 400, 'Password must be at least 4 characters');

  const { data: existing, error } = await supabase.from('users').select('*').eq('username', username).maybeSingle();
  if (error) throw error;

  let user = existing;
  if (!user) { // naya user auto-register
    const hash = await bcrypt.hash(password, 10);
    const { data: created, error: e2 } = await supabase
      .from('users').insert([{ username, password: hash, role: 'customer' }]).select().single();
    if (e2) throw e2;
    user = created;
  } else if (!(await bcrypt.compare(password, user.password))) {
    return fail(res, 401, 'Incorrect password');
  }
  res.json({ token: signToken(user, '7d'), user: publicUser(user) });
}));

app.post('/api/auth/admin-login', loginLimiter, wrap(async (req, res) => {
  const username = String((req.body || {}).username || '').trim();
  const password = String((req.body || {}).password || '');
  const { data: admin, error } = await supabase
    .from('users').select('*').eq('username', username).eq('role', 'admin').maybeSingle();
  if (error) throw error;
  if (!admin || !(await bcrypt.compare(password, admin.password))) return fail(res, 401, 'Invalid admin credentials');
  res.json({ token: signToken(admin, '1d') });
}));

// ---------- public ----------
app.get('/api/settings', wrap(async (req, res) => {
  const { data, error } = await supabase.from('store_settings').select('*');
  if (error) throw error;
  const settings = {};
  data.forEach((row) => { if (row.key !== 'coupons') settings[row.key] = row.value; }); // coupon codes private rahenge
  res.json(settings);
}));

app.get('/api/products', wrap(async (req, res) => {
  const { data, error } = await supabase.from('products').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  res.json(data);
}));

app.post('/api/coupons/validate', wrap(async (req, res) => {
  const code = String((req.body || {}).code || '').trim().toUpperCase();
  const coupons = await getSetting('coupons', []);
  const found = coupons.find((c) => String(c.code).toUpperCase() === code);
  if (!found) return fail(res, 404, 'Invalid coupon');
  res.json({ code: String(found.code).toUpperCase(), percent: Number(found.discount) });
}));

// ---------- customer ----------
app.put('/api/user/profile', authenticate, wrap(async (req, res) => {
  const b = req.body || {};
  const clip = (v, n) => String(v || '').trim().slice(0, n);
  const update = {
    full_name: clip(b.full_name, 100), mobile: clip(b.mobile, 15), location: clip(b.location, 200),
    house_number: clip(b.house_number, 100), pincode: clip(b.pincode, 10)
  };
  if (b.profile_photo !== undefined) {
    const photo = String(b.profile_photo || '');
    if (photo && !/^data:image\//.test(photo)) return fail(res, 400, 'Invalid photo');
    update.profile_photo = photo;
  }
  const { error } = await supabase.from('users').update(update).eq('username', req.user.username);
  if (error) throw error;
  res.json({ success: true });
}));

app.post('/api/orders', authenticate, wrap(async (req, res) => {
  const b = req.body || {};
  const phone = String(b.phone || '').trim();
  const pincode = String(b.pincode || '').trim();
  const houseNumber = String(b.houseNumber || '').trim().slice(0, 100);
  const fullAddress = String(b.fullAddress || '').trim().slice(0, 300);
  if (!/^\d{10}$/.test(phone)) return fail(res, 400, 'Enter a valid 10 digit mobile number');
  if (!/^\d{6}$/.test(pincode)) return fail(res, 400, 'Enter a valid 6 digit PIN code');
  if (!houseNumber || !fullAddress) return fail(res, 400, 'Address is required');
  if (!['COD', 'UPI'].includes(b.payment)) return fail(res, 400, 'Invalid payment method');
  if (!Array.isArray(b.items) || b.items.length < 1 || b.items.length > 50) return fail(res, 400, 'Cart is empty');

  // cart lines (same product + size merge)
  const lines = new Map();
  for (const it of b.items) {
    const id = Number(it.id), qty = Number(it.qty);
    if (!Number.isInteger(id) || !Number.isInteger(qty) || qty < 1 || qty > 100) return fail(res, 400, 'Invalid cart item');
    const size = String(it.size || 'N/A').slice(0, 10);
    const key = `${id}|${size}`;
    if (lines.has(key)) lines.get(key).qty += qty; else lines.set(key, { id, qty, size });
  }
  const entries = [...lines.values()];

  const ids = [...new Set(entries.map((e) => e.id))];
  const { data: prods, error: pe } = await supabase.from('products').select('id,name,price,stock').in('id', ids);
  if (pe) throw pe;
  const pmap = new Map(prods.map((p) => [p.id, p]));

  let subtotal = 0;
  const orderItems = [];
  for (const e of entries) {
    const p = pmap.get(e.id);
    if (!p) return fail(res, 400, 'A product in your cart is no longer available');
    subtotal += Number(p.price) * e.qty;
    orderItems.push({ id: p.id, name: p.name, price: Number(p.price), qty: e.qty, size: e.size });
  }

  // totals server par hi calculate hote hain (client par bharosa nahi)
  const pay = await getSetting('payment', { codCharge: 0, upiCashback: 0, codAvailable: true, onlineAvailable: true });
  if (b.payment === 'COD' && pay.codAvailable === false) return fail(res, 400, 'Cash on Delivery is not available');
  if (b.payment === 'UPI' && pay.onlineAvailable === false) return fail(res, 400, 'Online payment is not available');

  let discount = 0;
  if (b.couponCode) {
    const coupons = await getSetting('coupons', []);
    const code = String(b.couponCode).trim().toUpperCase();
    const c = coupons.find((x) => String(x.code).toUpperCase() === code);
    if (!c) return fail(res, 400, 'Invalid coupon');
    discount = Math.min(subtotal, Math.round(subtotal * (Number(c.discount) / 100)));
  }
  const shipping = subtotal >= 499 ? 0 : 49;
  const extra = b.payment === 'COD' ? Number(pay.codCharge) || 0 : -(Number(pay.upiCashback) || 0);
  const amount = Math.max(0, subtotal - discount + shipping + extra);

  // stock reserve (atomic)
  const reserved = [];
  try {
    for (const e of entries) {
      const ok = await adjustStock(e.id, -e.qty);
      if (!ok) {
        await restoreStock(reserved);
        return fail(res, 400, `Insufficient stock for ${pmap.get(e.id).name}`);
      }
      reserved.push({ id: e.id, qty: e.qty });
    }

    const row = {
      customer_username: req.user.username, phone, house_number: houseNumber, full_address: fullAddress,
      pincode, address: [houseNumber, fullAddress, pincode].join(', '), items: orderItems, amount,
      payment: b.payment, status: 'Processing',
      date: new Date().toLocaleDateString('en-IN', { timeZone: 'Asia/Kolkata' })
    };
    let orderId = null, lastError = null;
    for (let i = 0; i < 5; i++) {
      const candidate = '#BM' + crypto.randomInt(100000, 999999);
      const { error } = await supabase.from('orders').insert([{ id: candidate, ...row }]);
      if (!error) { orderId = candidate; lastError = null; break; }
      lastError = error;
      if (error.code !== '23505') break; // sirf duplicate id par retry
    }
    if (lastError) throw lastError;
    res.json({ success: true, orderId, amount });
  } catch (err) {
    if (!res.headersSent) await restoreStock(reserved);
    throw err;
  }
}));

app.get('/api/orders/my', authenticate, wrap(async (req, res) => {
  const { data, error } = await supabase.from('orders').select('*')
    .eq('customer_username', req.user.username).order('created_at', { ascending: false });
  if (error) throw error;
  res.json(data);
}));

app.patch('/api/orders/:id/cancel', authenticate, wrap(async (req, res) => {
  const reason = String((req.body || {}).cancel_reason || '').trim().slice(0, 300);
  const { data: order, error } = await supabase.from('orders').select('*')
    .eq('id', req.params.id).eq('customer_username', req.user.username).maybeSingle();
  if (error) throw error;
  if (!order) return fail(res, 404, 'Order not found');
  if (order.status !== 'Processing') return fail(res, 400, 'Only orders in Processing can be cancelled');

  const { data: updated, error: e2 } = await supabase.from('orders')
    .update({ status: 'Cancelled', cancel_reason: reason }).eq('id', order.id).eq('status', 'Processing').select('id');
  if (e2) throw e2;
  if (updated && updated.length) await restoreStock(order.items);
  res.json({ success: true });
}));

app.post('/api/products/:id/reviews', authenticate, wrap(async (req, res) => {
  const rating = Number((req.body || {}).rating);
  const text = String((req.body || {}).text || '').trim().slice(0, 1000);
  const images = Array.isArray((req.body || {}).images)
    ? req.body.images.filter((i) => /^data:image\//.test(String(i))).slice(0, 3) : [];
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) return fail(res, 400, 'Rating must be 1 to 5');
  if (!text) return fail(res, 400, 'Please write a review');

  const { data: p, error } = await supabase.from('products').select('reviews_data').eq('id', req.params.id).maybeSingle();
  if (error) throw error;
  if (!p) return fail(res, 404, 'Product not found');

  const review = { user: req.user.username, rating, text, images };
  const others = (p.reviews_data || []).filter((r) => r.user !== req.user.username); // ek user = ek review
  const reviews = [...others, review];
  const avg = reviews.reduce((s, r) => s + r.rating, 0) / reviews.length;
  const { error: e2 } = await supabase.from('products')
    .update({ reviews_data: reviews, reviews_count: reviews.length, rating: Number(avg.toFixed(1)) })
    .eq('id', req.params.id);
  if (e2) throw e2;
  res.json({ success: true });
}));

// ---------- admin ----------
app.get('/api/admin/orders', authenticate, requireAdmin, wrap(async (req, res) => {
  const { data, error } = await supabase.from('orders').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  res.json(data);
}));

app.patch('/api/admin/orders/:id/status', authenticate, requireAdmin, wrap(async (req, res) => {
  const status = (req.body || {}).status;
  if (!STATUSES.includes(status)) return fail(res, 400, 'Invalid status');
  const { data: order, error } = await supabase.from('orders').select('*').eq('id', req.params.id).maybeSingle();
  if (error) throw error;
  if (!order) return fail(res, 404, 'Order not found');
  if (order.status === 'Cancelled' && status !== 'Cancelled') return fail(res, 400, 'Cancelled order cannot be reopened');

  const { error: e2 } = await supabase.from('orders').update({ status }).eq('id', order.id);
  if (e2) throw e2;
  if (status === 'Cancelled' && order.status !== 'Cancelled') await restoreStock(order.items);
  res.json({ success: true });
}));

function cleanProduct(b) {
  const out = {};
  const str = (k, max) => { if (b[k] !== undefined) out[k] = String(b[k]).trim().slice(0, max); };
  const num = (k) => {
    if (b[k] === undefined) return;
    const n = Number(b[k]);
    if (!Number.isFinite(n) || n < 0) throw new HttpError(400, `Invalid ${k}`);
    out[k] = n;
  };
  str('name', 150); str('subtitle', 200); str('category', 60); str('subcategory', 60); str('description', 3000);
  num('price'); num('mrp'); num('stock');
  if (out.stock !== undefined) out.stock = Math.floor(out.stock);
  if (b.image !== undefined) {
    const img = String(b.image);
    if (!/^(https?:\/\/|data:image\/)/.test(img)) throw new HttpError(400, 'Invalid image');
    out.image = img;
  }
  if (Array.isArray(b.images)) out.images = b.images.map(String).filter((i) => /^(https?:\/\/|data:image\/)/.test(i)).slice(0, 6);
  return out;
}

app.post('/api/admin/products', authenticate, requireAdmin, wrap(async (req, res) => {
  const p = cleanProduct(req.body || {});
  if (!p.name || p.price === undefined || p.mrp === undefined || !p.category) return fail(res, 400, 'Name, category, price and MRP are required');
  if (p.mrp < p.price) return fail(res, 400, 'MRP cannot be less than selling price');
  p.sku = (req.body.sku && String(req.body.sku).trim()) || 'BM-' + crypto.randomInt(100000, 999999);
  if (p.stock === undefined) p.stock = 0;
  if (!p.images || !p.images.length) p.images = p.image ? [p.image] : [];
  const { data, error } = await supabase.from('products').insert([p]).select().single();
  if (error) return fail(res, 400, error.message);
  res.json(data);
}));

app.patch('/api/admin/products/:id', authenticate, requireAdmin, wrap(async (req, res) => {
  const p = cleanProduct(req.body || {});
  if (!Object.keys(p).length) return fail(res, 400, 'Nothing to update');
  if (p.price !== undefined && p.mrp !== undefined && p.mrp < p.price) return fail(res, 400, 'MRP cannot be less than selling price');
  const { error } = await supabase.from('products').update(p).eq('id', req.params.id);
  if (error) return fail(res, 400, error.message);
  res.json({ success: true });
}));

app.delete('/api/admin/products/:id', authenticate, requireAdmin, wrap(async (req, res) => {
  const { error } = await supabase.from('products').delete().eq('id', req.params.id);
  if (error) throw error;
  res.json({ success: true });
}));

app.get('/api/admin/settings', authenticate, requireAdmin, wrap(async (req, res) => {
  const { data, error } = await supabase.from('store_settings').select('*');
  if (error) throw error;
  const settings = {};
  data.forEach((row) => { settings[row.key] = row.value; });
  res.json(settings);
}));

app.put('/api/admin/settings', authenticate, requireAdmin, wrap(async (req, res) => {
  const { key, value } = req.body || {};
  const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
  const rules = {
    payment: (v) => isObj(v) && Number.isFinite(Number(v.codCharge)) && Number.isFinite(Number(v.upiCashback)),
    support: (v) => isObj(v) && typeof v.email === 'string' && typeof v.whatsapp === 'string',
    offer_text: (v) => typeof v === 'string' && v.length <= 200,
    coupons: (v) => Array.isArray(v) && v.every((c) => c && typeof c.code === 'string' && Number(c.discount) > 0 && Number(c.discount) <= 90),
    notifications: (v) => Array.isArray(v) && v.length <= 100
  };
  if (!rules[key]) return fail(res, 400, 'Unknown setting');
  if (!rules[key](value)) return fail(res, 400, 'Invalid value');
  const { error } = await supabase.from('store_settings').upsert({ key, value }, { onConflict: 'key' });
  if (error) throw error;
  res.json({ success: true });
}));

// ---------- errors ----------
app.use('/api', (req, res) => fail(res, 404, 'Not found'));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (err.type === 'entity.too.large') return fail(res, 413, 'Image/data too large');
  if (err.status && err.status < 500) return fail(res, err.status, err.message);
  console.error(err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

// ---------- start ----------
async function seedAdmin() {
  if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    console.warn('ADMIN_USERNAME / ADMIN_PASSWORD not set - admin account not created.');
    return;
  }
  const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
  const { data: existing } = await supabase.from('users').select('id').eq('username', ADMIN_USERNAME).maybeSingle();
  if (existing) await supabase.from('users').update({ password: hash, role: 'admin' }).eq('id', existing.id);
  else await supabase.from('users').insert([{ username: ADMIN_USERNAME, password: hash, role: 'admin' }]);
  console.log('Admin account ready:', ADMIN_USERNAME);
}

const PORT = process.env.PORT || 3000;
seedAdmin()
  .catch((e) => console.error('Admin seed failed:', e.message))
  .finally(() => app.listen(PORT, () => console.log(`Server running on port ${PORT}`)));
