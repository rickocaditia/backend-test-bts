const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = 'bts_secret_key_123';

// In-Memory Database
let users = [];
let products = [
  {
    id: 1,
    title: "Awesome T-Shirt",
    price: 99.99,
    description: "High-quality cotton t-shirt",
    category: "Clothes",
    images: ["https://placeimg.com/640/480/any"],
    created_at: "2025-01-01 15:01:04",
    created_by: "Jhon Doe",
    created_by_id: "1",
    updated_at: "2025-01-01 15:01:04",
    updated_by: "Jhon Doe",
    updated_by_id: "1"
  }
];

// Middleware Auth
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: "Unauthorized: Token tidak ditemukan" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Forbidden: Token tidak valid" });
    req.user = user;
    next();
  });
}

// 1. AUTH REGISTER
app.post('/api/auth/register', async (req, res) => {
  const { username, password, password_confirmation } = req.body;
  if (!username || !password || password !== password_confirmation) {
    return res.status(400).json({ message: "Validasi gagal: pastikan password dan konfirmasi sama." });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ id: users.length + 1, username, password: hashedPassword });
  res.status(201).json({ message: "Registrasi berhasil", username });
});

// 2. AUTH LOGIN
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Username atau password salah" });
  }
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1d' });
  res.json({
    authentication_token: token,
    refresh_token: token
  });
});

// 3. GET ALL PRODUCTS (Search, Category, Pagination)
app.get('/api/products', (req, res) => {
  let { search, category, limit = 10, page = 1 } = req.query;
  let result = [...products];

  if (search) {
    result = result.filter(p => p.title.toLowerCase().includes(search.toLowerCase()));
  }
  if (category) {
    result = result.filter(p => p.category.toLowerCase() === category.toLowerCase());
  }

  const start = (page - 1) * limit;
  const paginated = result.slice(start, start + Number(limit));

  res.json({
    total: result.length,
    page: Number(page),
    limit: Number(limit),
    data: paginated
  });
});

// 4. GET PRODUCT BY ID
app.get('/api/products/:id', (req, res) => {
  const product = products.find(p => p.id == req.params.id);
  if (!product) return res.status(404).json({ message: "Produk tidak ditemukan" });
  res.json(product);
});

// 5. POST PRODUCT (Protected)
app.post('/api/products', authenticateToken, (req, res) => {
  const { title, price, description, category, images } = req.body;
  if (!title || !price || !category || !images || !Array.isArray(images) || images.length === 0) {
    return res.status(400).json({ message: "Validasi gagal: title, price, category, dan images minimal 1 wajib diisi." });
  }

  const newProduct = {
    id: products.length > 0 ? products[products.length - 1].id + 1 : 1,
    title,
    price,
    description: description || "",
    category,
    images,
    created_at: new Date().toISOString().replace('T', ' ').substring(0, 19),
    created_by: req.user.username,
    created_by_id: String(req.user.id),
    updated_at: new Date().toISOString().replace('T', ' ').substring(0, 19),
    updated_by: req.user.username,
    updated_by_id: String(req.user.id)
  };

  products.push(newProduct);
  res.status(201).json(newProduct);
});

// 6. PUT PRODUCT (Protected)
app.put('/api/products/:id', authenticateToken, (req, res) => {
  const index = products.findIndex(p => p.id == req.params.id);
  if (index === -1) return res.status(404).json({ message: "Produk tidak ditemukan" });

  const { title, price, description, category, images } = req.body;
  products[index] = {
    ...products[index],
    title: title || products[index].title,
    price: price || products[index].price,
    description: description !== undefined ? description : products[index].description,
    category: category || products[index].category,
    images: images || products[index].images,
    updated_at: new Date().toISOString().replace('T', ' ').substring(0, 19),
    updated_by: req.user.username,
    updated_by_id: String(req.user.id)
  };

  res.json(products[index]);
});

// 7. DELETE PRODUCT (Protected)
app.delete('/api/products/:id', authenticateToken, (req, res) => {
  const index = products.findIndex(p => p.id == req.params.id);
  if (index === -1) return res.status(404).json({ message: "Produk tidak ditemukan" });

  const deleted = products.splice(index, 1);
  res.json({ message: "Produk berhasil dihapus", data: deleted[0] });
});

const PORT = process.env.PORT || 2026;

// Jalankan app.listen hanya jika dijalankan secara lokal (bukan di Vercel)
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => console.log(`Server berjalan di port ${PORT}`));
}

// Wajib diexport agar Vercel bisa membaca aplikasi Express Anda
module.exports = app;