require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
// Multiple photos (base64) upload karne ke liye limit badha di gayi hai
app.use(express.json({ limit: '50mb' })); 

const supabaseUrl = process.env.SUPABASE_URL;
// Render ki key problem fix karne ke liye dono options support kiye hain
const supabaseKey = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error("Missing Supabase Keys. Check Environment Variables!");
}

const supabase = createClient(supabaseUrl, supabaseKey);
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretbharatmart123';

// Helper: Verify Token (User / Admin)
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token missing' });
  try { 
    req.user = jwt.verify(token, JWT_SECRET); 
    next(); 
  } catch (e) { 
    res.status(401).json({ error: 'Invalid Token' }); 
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
};

// ----------------- AUTH & PROFILE ROUTES -----------------
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const { data: users } = await supabase.from('users').select('*').eq('username', username);
  let user = users && users.length > 0 ? users[0] : null;

  if (user) {
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Wrong password' });
  } else {
    const hashed = await bcrypt.hash(password, 10);
    const { data: newUser, error } = await supabase.from('users').insert([{ username, password: hashed, role: 'customer' }]).select();
    if (error) return res.status(400).json({ error: 'Failed to register' });
    user = newUser[0];
  }
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ 
    token, 
    user: { id: user.id, username: user.username, role: user.role, full_name: user.full_name, mobile: user.mobile, location: user.location, house_number: user.house_number, pincode: user.pincode, profile_photo: user.profile_photo } 
  });
});

app.post('/api/auth/admin-login', async (req, res) => {
  const { username, password } = req.body;
  const { data: users } = await supabase.from('users').select('*').eq('username', username).eq('role', 'admin');
  if (!users || users.length === 0) return res.status(401).json({ error: 'Admin account not found' });
  
  const valid = await bcrypt.compare(password, users[0].password);
  if (!valid && password !== users[0].password) return res.status(401).json({ error: 'Wrong admin password' });
  
  const token = jwt.sign({ id: users[0].id, username: users[0].username, role: 'admin' }, JWT_SECRET, { expiresIn: '1d' });
  res.json({ token });
});

app.put('/api/user/profile', authenticate, async (req, res) => {
  const { full_name, mobile, location, house_number, pincode, profile_photo } = req.body;
  const { error } = await supabase.from('users').update({ 
    full_name, mobile, location, house_number, pincode, profile_photo 
  }).eq('username', req.user.username);
  
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ----------------- CATALOG / PUBLIC ROUTES -----------------
app.get('/api/products', async (req, res) => {
  const { data, error } = await supabase.from('products').select('*').order('id', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/settings', async (req, res) => {
  const { data } = await supabase.from('store_settings').select('*');
  const settings = {};
  if (data) data.forEach(row => settings[row.key] = row.value);
  res.json(settings);
});

// ----------------- REVIEWS -----------------
app.post('/api/products/:id/reviews', authenticate, async (req, res) => {
  const { rating, text, images } = req.body;
  const { data: prod } = await supabase.from('products').select('reviews_data').eq('id', req.params.id).maybeSingle();
  
  const existingReviews = prod?.reviews_data || [];
  const newReview = { user: req.user.username, rating: Number(rating), text, images: images || [], date: new Date().toLocaleDateString('en-IN') };
  existingReviews.push(newReview);
  
  const newCount = existingReviews.length;
  const newAvg = existingReviews.reduce((sum, r) => sum + r.rating, 0) / newCount;
  
  const { error } = await supabase.from('products').update({ 
    reviews_data: existingReviews, reviews_count: newCount, rating: newAvg 
  }).eq('id', req.params.id);
  
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ----------------- COUPONS -----------------
app.post('/api/coupons/verify', async (req, res) => {
  const { code } = req.body;
  const { data } = await supabase.from('store_settings').select('value').eq('key', 'coupons').maybeSingle();
  const couponsList = (data && data.value) ? data.value : [];
  const found = couponsList.find(c => c.code.toUpperCase() === code.toUpperCase());
  if (found) res.json({ discount: found.discount, type: 'percentage' });
  else res.status(400).json({ error: 'Invalid or expired coupon' });
});

// ----------------- CUSTOMER ORDERS -----------------
app.post('/api/orders', authenticate, async (req, res) => {
  const { phone, houseNumber, fullAddress, address, pincode, payment, items, couponCode } = req.body;
  const finalAddress = fullAddress || address;
  let subtotal = 0;
  
  // Checking stock
  for (const item of items) {
    const { data: prod } = await supabase.from('products').select('price, stock').eq('id', item.id).maybeSingle();
    if (!prod || prod.stock < item.qty) return res.status(400).json({ error: `Not enough stock for ${item.name}` });
    subtotal += prod.price * item.qty;
  }

  let discount = 0;
  if (couponCode) {
    const { data: cData } = await supabase.from('store_settings').select('value').eq('key', 'coupons').maybeSingle();
    const cList = cData ? cData.value : [];
    const found = cList.find(c => c.code.toUpperCase() === couponCode.toUpperCase());
    if (found) discount = Math.round(subtotal * found.discount / 100);
  }

  const { data: payData } = await supabase.from('store_settings').select('value').eq('key', 'payment').maybeSingle();
  const paySet = payData ? payData.value : { codCharge: 49, upiCashback: 0 };
  let shipping = (subtotal === 0 || subtotal >= 499) ? 0 : 49;
  let extra = payment === 'COD' ? Number(paySet.codCharge) : (payment === 'UPI' ? -Number(paySet.upiCashback) : 0);
  const total = Math.max(0, subtotal - discount + shipping + extra);

  const orderId = 'ORD' + Date.now().toString().slice(-6);
  const date = new Date().toLocaleDateString('en-IN');

  const { error } = await supabase.from('orders').insert([{
    id: orderId, customer_username: req.user.username, phone, houseNumber, address: finalAddress, pincode,
    payment, items, amount: total, status: 'Processing', date
  }]);
  if (error) return res.status(500).json({ error: 'Order failed' });

  // Update Stock
  for (const item of items) {
    await supabase.rpc('decrement_stock', { p_id: item.id, qty: item.qty }).catch(console.error);
  }
  res.json({ success: true, orderId, amount: total });
});

app.get('/api/orders/my', authenticate, async (req, res) => {
  const { data, error } = await supabase.from('orders').select('*').eq('customer_username', req.user.username).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/orders/:id/cancel', authenticate, async (req, res) => {
  const { cancel_reason } = req.body;
  const { error } = await supabase.from('orders').update({ status: 'Cancelled', cancel_reason }).eq('id', req.params.id).eq('customer_username', req.user.username);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ----------------- ADMIN ROUTES -----------------
app.get('/api/admin/orders', authenticate, requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('orders').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/admin/orders/:id/status', authenticate, requireAdmin, async (req, res) => {
  const { status } = req.body;
  const { error } = await supabase.from('orders').update({ status }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.post('/api/admin/products', authenticate, requireAdmin, async (req, res) => {
  const p = req.body;
  const sku = 'SKU' + Math.floor(Math.random() * 10000);
  const { error } = await supabase.from('products').insert([{
    name: p.name, subtitle: p.subtitle, category: p.category, subcategory: p.subcategory,
    price: p.price, mrp: p.mrp, stock: p.stock, description: p.description, 
    image: p.image, images: p.images, colors: p.colors, sizes: p.sizes, sku: sku
  }]);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.patch('/api/admin/products/:id', authenticate, requireAdmin, async (req, res) => {
  const { price, mrp, stock } = req.body;
  const { error } = await supabase.from('products').update({ price, mrp, stock }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.delete('/api/admin/products/:id', authenticate, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('products').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.get('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('store_settings').select('*');
  if (error) return res.status(500).json({ error: error.message });
  const settings = {}; data.forEach(row => settings[row.key] = row.value);
  res.json(settings);
});

// FIXED: Admin settings update (Unique Constraint error fixed here)
app.put('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
  const { key, value } = req.body;
  
  // Checking existing setting by 'key' using maybeSingle() to avoid crashes
  const { data: existing } = await supabase.from('store_settings').select('key').eq('key', key).maybeSingle();
  
  let error;
  if (existing) {
    const resUpdate = await supabase.from('store_settings').update({ value }).eq('key', key);
    error = resUpdate.error;
  } else {
    const resInsert = await supabase.from('store_settings').insert([{ key, value }]);
    error = resInsert.error;
  }
  
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Bharat Mart Backend running on port ${PORT}`));
