require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretbharatmart123';

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token missing' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); } 
  catch (e) { res.status(401).json({ error: 'Invalid Token' }); }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
};

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
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
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

app.post('/api/coupons/verify', async (req, res) => {
  const { code } = req.body;
  const { data } = await supabase.from('store_settings').select('value').eq('key', 'coupons').maybeSingle();
  const couponsList = (data && data.value) ? data.value : [];
  const found = couponsList.find(c => c.code.toUpperCase() === code.toUpperCase());
  if (found) res.json({ discount: found.discount });
  else res.status(400).json({ error: 'Invalid or expired coupon' });
});

app.post('/api/orders', authenticate, async (req, res) => {
  const { phone, houseNumber, address, pincode, payment, items, couponCode } = req.body;
  let subtotal = 0;
  
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
    id: orderId, customer_username: req.user.username, phone, houseNumber, address, pincode,
    payment, items, amount: total, status: 'Processing', date
  }]);
  if (error) return res.status(500).json({ error: 'Order failed' });

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
    image: p.image, sku: sku
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

app.put('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
  const { key, value } = req.body;
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
