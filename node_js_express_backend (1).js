/**
 * NovaStore E-Commerce - Node.js Express Backend
 * 
 * Dependencies required (run `npm init -y && npm install express sqlite3 cors bcryptjs jsonwebtoken`)
 * Architecture: REST API with SQLite database, JWT authentication, and full CRUD for products, users, and orders.
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'novastore_super_secret_key_2026';

// Middleware
app.use(express.json());
app.use(cors());

// Initialize SQLite Database
const db = new sqlite3.Database('./novastore.db', (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to SQLite database.');
        initializeDatabase();
    }
});

// Database Schema & Seed Data
function initializeDatabase() {
    db.serialize(() => {
        // Users Table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Products Table
        db.run(`CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            rating REAL DEFAULT 5.0,
            reviews_count INTEGER DEFAULT 0,
            in_stock BOOLEAN DEFAULT 1,
            image TEXT NOT NULL,
            description TEXT,
            specs TEXT -- Stored as comma-separated values or JSON
        )`);

        // Orders Table
        db.run(`CREATE TABLE IF NOT EXISTS orders (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            customer_name TEXT,
            address TEXT,
            subtotal REAL,
            tax REAL,
            total REAL,
            status TEXT DEFAULT 'Processing',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);

        // Order Items Table
        db.run(`CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id TEXT,
            product_id INTEGER,
            product_name TEXT,
            price REAL,
            quantity INTEGER,
            FOREIGN KEY(order_id) REFERENCES orders(id)
        )`);

        // Seed initial products if table is empty
        db.get(`SELECT COUNT(*) as count FROM products`, (err, row) => {
            if (row.count === 0) {
                const sampleProducts = [
                    ["Apex Pro Wireless Headphones", "Electronics", 299.99, 4.8, 142, 1, "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=800&q=80", "Industry-leading active noise cancellation.", "Bluetooth 5.3,40h Battery,ANC"],
                    ["NovaWatch Series X", "Electronics", 399.99, 4.9, 289, 1, "https://images.unsplash.com/photo-1523275335684-37898b6baf30?auto=format&fit=crop&w=800&q=80", "Advanced titanium fitness smartwatch.", "Titanium Body,AMOLED,GPS"],
                    ["Urban Minimalist Bomber Jacket", "Apparel", 145.00, 4.7, 84, 1, "https://images.unsplash.com/photo-1548883354-7622d03a27d0?auto=format&fit=crop&w=800&q=80", "Weather-resistant lightweight bomber.", "Water Repellent,Quilted Lining"]
                ];

                const stmt = db.prepare(`INSERT INTO products (name, category, price, rating, reviews_count, in_stock, image, description, specs) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
                sampleProducts.forEach(p => stmt.run(p));
                stmt.finalize();
                console.log('Seeded initial products into database.');
            }
        });
    });
}

// Authentication Middleware
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}

/* ==========================
   PRODUCT API ROUTES
   ========================== */

// Get all products (with optional category filter & search)
app.get('/api/products', (req, res) => {
    const { category, search } = req.query;
    let query = `SELECT * FROM products WHERE 1=1`;
    let params = [];

    if (category && category !== 'All') {
        query += ` AND category = ?`;
        params.push(category);
    }
    if (search) {
        query += ` AND (name LIKE ? OR description LIKE ?)`;
        params.push(`%${search}%`, `%${search}%`);
    }

    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        // Format specs back to array
        const formatted = rows.map(p => ({ ...p, specs: p.specs ? p.specs.split(',') : [] }));
        res.json(formatted);
    });
});

// Get single product detail
app.get('/api/products/:id', (req, res) => {
    db.get(`SELECT * FROM products WHERE id = ?`, [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'Product not found' });
        row.specs = row.specs ? row.specs.split(',') : [];
        res.json(row);
    });
});

/* ==========================
   USER AUTHENTICATION ROUTES
   ========================== */

// Register User
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (name, email, password) VALUES (?, ?, ?)`, [name, email, hashedPassword], function(err) {
            if (err) {
                return res.status(400).json({ error: 'Email already in use or invalid' });
            }
            const token = jwt.sign({ id: this.lastID, email, name }, JWT_SECRET, { expiresIn: '7d' });
            res.status(201).json({ message: 'User registered successfully', token, user: { id: this.lastID, name, email } });
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Login User
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(400).json({ error: 'Invalid email or password' });

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return res.status(400).json({ error: 'Invalid email or password' });

        const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ message: 'Logged in successfully', token, user: { id: user.id, name: user.name, email: user.email } });
    });
});

/* ==========================
   ORDER PROCESSING ROUTES
   ========================== */

// Create Order (Protected)
app.post('/api/orders', verifyToken, (req, res) => {
    const { address, items, subtotal, tax, total } = req.body;
    if (!items || items.length === 0 || !address) {
        return res.status(400).json({ error: 'Order items and shipping address are required' });
    }

    const orderId = 'ORD-' + Math.floor(100000 + Math.random() * 900000);
    const userId = req.user.id;
    const customerName = req.user.name;

    db.serialize(() => {
        db.run('BEGIN TRANSACTION');

        db.run(`INSERT INTO orders (id, user_id, customer_name, address, subtotal, tax, total) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [orderId, userId, customerName, address, subtotal, tax, total], (err) => {
                if (err) {
                    db.run('ROLLBACK');
                    return res.status(500).json({ error: err.message });
                }

                const stmt = db.prepare(`INSERT INTO order_items (order_id, product_id, product_name, price, quantity) VALUES (?, ?, ?, ?, ?)`);
                items.forEach(item => {
                    stmt.run(orderId, item.id, item.name, item.price, item.quantity);
                });
                stmt.finalize();

                db.run('COMMIT', (err) => {
                    if (err) return res.status(500).json({ error: err.message });
                    res.status(201).json({ message: 'Order created successfully', orderId, total });
                });
            });
    });
});

// Get User Orders (Protected)
app.get('/api/orders', verifyToken, (req, res) => {
    const userId = req.user.id;
    db.all(`SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC`, [userId], (err, orders) => {
        if (err) return res.status(500).json({ error: err.message });
        
        // Fetch items for each order
        const orderPromises = orders.map(order => {
            return new Promise((resolve, reject) => {
                db.all(`SELECT * FROM order_items WHERE order_id = ?`, [order.id], (err, items) => {
                    if (err) reject(err);
                    resolve({ ...order, items });
                });
            });
        });

        Promise.all(orderPromises)
            .then(fullOrders => res.json(fullOrders))
            .catch(err => res.status(500).json({ error: err.message }));
    });
});

// Start Express Server
app.listen(PORT, () => {
    console.log(`NovaStore Express Backend running on port ${PORT}`);
});