require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const supabaseUrl = process.env.SUPABASE_URL || "";
const supabaseKey = process.env.SUPABASE_SERVICE_KEY || "";
const supabase = createClient(supabaseUrl, supabaseKey);
const JWT_SECRET = process.env.JWT_SECRET || "bharat_mart_secret_123";

// --- MIDDLEWARE ---
const authenticate = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ error: "Missing token" });
        const token = authHeader.split(' ')[1];
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) return res.status(403).json({ error: "Invalid token" });
            req.user = user;
            next();
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
};

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Admin access required" });
    next();
};

// --- AUTHENTICATION ROUTES ---
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!supabaseUrl || !supabaseKey) return res.status(500).json({ error: "Render par SUPABASE_URL ya KEY missing hai." });

        let { data: user, error: selErr } = await supabase.from('users').select('*').eq('username', username).single();
        if (selErr && selErr.code !== 'PGRST116') return res.status(400).json({ error: "DB Error: " + selErr.message });
        
        if (!user) { 
            const { data: newUser, error: insErr } = await supabase.from('users').insert([{ username, password, role: 'customer' }]).select().single();
            if (insErr) return res.status(400).json({ error: "Table Error: Supabase me schema.sql fir se run karein." });
            user = newUser;
        } else if (user.password !== password) {
            return res.status(401).json({ error: "Incorrect Password" });
        }
        
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { username: user.username, full_name: user.full_name, mobile: user.mobile, location: user.location, house_number: user.house_number, pincode: user.pincode, profile_photo: user.profile_photo } });
    } catch (error) { res.status(500).json({ error: "Server Error: " + error.message }); }
});

app.post('/api/admin/products', authenticate, requireAdmin, async (req, res) => {
    try {
        // Naya code jo automatically SKU bana dega
        if (!req.body.sku) {
            req.body.sku = "PRD-" + Date.now();
        }
        const { data, error } = await supabase.from('products').insert([req.body]).select();
        if (error) return res.status(400).json({ error: error.message });
        res.json(data[0]);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// --- PUBLIC STORE ROUTES ---
app.get('/api/settings', async (req, res) => {
    try {
        const { data, error } = await supabase.from('store_settings').select('*');
        if (error) return res.status(400).json({ error: error.message });
        const settings = {};
        if(data) data.forEach(item => settings[item.key] = item.value);
        res.json(settings);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/products', async (req, res) => {
    try {
        const { data, error } = await supabase.from('products').select('*').order('created_at', { ascending: false });
        if (error) return res.status(400).json({ error: error.message });
        res.json(data || []);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// --- CUSTOMER ROUTES ---
app.put('/api/user/profile', authenticate, async (req, res) => {
    try {
        const { full_name, mobile, location, house_number, pincode, profile_photo } = req.body;
        const { error } = await supabase.from('users').update({ full_name, mobile, location, house_number, pincode, profile_photo }).eq('username', req.user.username);
        if (error) return res.status(400).json({ error: error.message });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/orders', authenticate, async (req, res) => {
    try {
        const { phone, houseNumber, fullAddress, pincode, address, payment, items, amount, date } = req.body;
        let calculatedTotal = 0;
        for (let item of items) {
            const { data: p } = await supabase.from('products').select('stock, price').eq('id', item.id).single();
            if (!p || p.stock < item.qty) return res.status(400).json({ error: `Insufficient stock for ${item.name}` });
            calculatedTotal += (p.price * item.qty);
            await supabase.from('products').update({ stock: p.stock - item.qty }).eq('id', item.id);
        }
        const orderId = "#BM" + Math.floor(10000 + Math.random() * 90000);
        const { error } = await supabase.from('orders').insert([{
            id: orderId, customer_username: req.user.username, phone, house_number: houseNumber, full_address: fullAddress, pincode, address, items, amount, payment, date
        }]);
        if (error) return res.status(400).json({ error: error.message });
        res.json({ success: true, orderId });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/orders/my', authenticate, async (req, res) => {
    try {
        const { data, error } = await supabase.from('orders').select('*').eq('customer_username', req.user.username).order('created_at', { ascending: false });
        if (error) return res.status(400).json({ error: error.message });
        res.json(data || []);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.patch('/api/orders/:id/cancel', authenticate, async (req, res) => {
    try {
        const { cancel_reason } = req.body;
        const { error } = await supabase.from('orders').update({ status: 'Cancelled', cancel_reason }).eq('id', req.params.id).eq('customer_username', req.user.username);
        if (error) return res.status(400).json({ error: error.message });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/products/:id/reviews', authenticate, async (req, res) => {
    try {
        const { rating, text, images, image } = req.body;
        const { data: p, error: selErr } = await supabase.from('products').select('reviews_data').eq('id', req.params.id).single();
        if (selErr) return res.status(400).json({ error: selErr.message });
        const newReview = { user: req.user.username, rating, text, images, image };
        const reviews = p.reviews_data ? [...p.reviews_data, newReview] : [newReview];
        const { error } = await supabase.from('products').update({ reviews_data: reviews }).eq('id', req.params.id);
        if (error) return res.status(400).json({ error: error.message });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// --- ADMIN ROUTES ---
app.get('/api/admin/orders', authenticate, requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase.from('orders').select('*').order('created_at', { ascending: false });
        if (error) return res.status(400).json({ error: error.message });
        res.json(data || []);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.patch('/api/admin/orders/:id/status', authenticate, requireAdmin, async (req, res) => {
    try {
        const { error } = await supabase.from('orders').update({ status: req.body.status }).eq('id', req.params.id);
        if (error) return res.status(400).json({ error: error.message });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/admin/products', authenticate, requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase.from('products').insert([req.body]).select();
        if (error) return res.status(400).json({ error: error.message });
        res.json(data[0]);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.patch('/api/admin/products/:id', authenticate, requireAdmin, async (req, res) => {
    try {
        const { error } = await supabase.from('products').update(req.body).eq('id', req.params.id);
        if (error) return res.status(400).json({ error: error.message });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.delete('/api/admin/products/:id', authenticate, requireAdmin, async (req, res) => {
    try {
        const { error } = await supabase.from('products').delete().eq('id', req.params.id);
        if (error) return res.status(400).json({ error: error.message });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
    try {
        const { key, value } = req.body;
        const { error } = await supabase.from('store_settings').update({ value }).eq('key', key);
        if (error) return res.status(400).json({ error: error.message });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
