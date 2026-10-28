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
            if (insErr) return res.status(400).json({ error: "Table Error: schema check karein." });
            user = newUser;
        } else if (user.password !== password) {
            return res.status(401).json({ error: "Incorrect Password" });
        }
        
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { username: user.username, full_name: user.full_name, mobile: user.mobile } });
    } catch (error) { res.status(500).json({ error: "Server Error: " + error.message }); }
});

app.post('/api/auth/admin-login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const { data: admin, error } = await supabase.from('users').select('*').eq('username', username).eq('role', 'admin').single();
        if (error && error.code !== 'PGRST116') return res.status(400).json({ error: "DB Error: " + error.message });
        if (!admin || admin.password !== password) return res.status(401).json({ error: "Invalid Admin Credentials" });
        const token = jwt.sign({ id: admin.id, username: admin.username, role: admin.role }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ token });
    } catch (error) { res.status(500).json({ error: "Server Error: " + error.message }); }
});

// --- COUPON ROUTE (New) ---
app.post('/api/verify-coupon', async (req, res) => {
    const { code } = req.body;
    // Aap yahan apna coupon code aur discount set kar sakte hain
    if (code && code.toUpperCase() === 'WELCOME50') {
        return res.json({ success: true, discount: 50, type: 'fixed' });
    }
    res.status(400).json({ error: "Invalid Coupon Code" });
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
app.post('/api/orders', authenticate, async (req, res) => {
    try {
        const { phone, houseNumber, fullAddress, pincode, address, payment, items, date } = req.body;
        let calculatedTotal = 0;
        for (let item of items) {
            const { data: p } = await supabase.from('products').select('stock, price').eq('id', item.id).single();
            if (!p || p.stock < item.qty) return res.status(400).json({ error: `Insufficient stock for ${item.name}` });
            calculatedTotal += (p.price * item.qty);
            await supabase.from('products').update({ stock: p.stock - item.qty }).eq('id', item.id);
        }
        
        let finalAmount = req.body.amount || req.body.totalAmount || req.body.total || calculatedTotal;
        const orderId = "#BM" + Math.floor(10000 + Math.random() * 90000);
        
        const { error } = await supabase.from('orders').insert([{
            id: orderId, customer_username: req.user.username, phone, house_number: houseNumber, full_address: fullAddress, pincode, address, items, amount: finalAmount, payment, date
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

// --- ADMIN ROUTES ---
// Dashboard Stats (New)
app.get('/api/admin/dashboard', authenticate, requireAdmin, async (req, res) => {
    try {
        const { data: orders } = await supabase.from('orders').select('*');
        const { data: products } = await supabase.from('products').select('*');
        let totalRevenue = 0;
        let pending = 0;
        if (orders) {
            orders.forEach(o => {
                if (o.status !== 'Cancelled') totalRevenue += Number(o.amount || 0);
                if (o.status === 'Pending') pending++;
            });
        }
        res.json({
            totalOrders: orders ? orders.length : 0,
            totalProducts: products ? products.length : 0,
            revenue: totalRevenue,
            pendingOrders: pending
        });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/admin/products', authenticate, requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase.from('products').select('*').order('created_at', { ascending: false });
        if (error) return res.status(400).json({ error: error.message });
        res.json(data || []);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

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
        if (!req.body.sku) req.body.sku = "PRD-" + Date.now();
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
