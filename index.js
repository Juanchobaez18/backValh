import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import path from 'path';
import { fileURLToPath } from 'url';
import { initDb, getDbConnection } from './db.js';

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'valhalla_mystic_key_12345';

// CORS configuration — allows the frontend origin in production
const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
  : ['http://localhost:5173'];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Initialize Database schemas and seed data
await initDb();

// Middleware to authenticate JWT tokens
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Expecting "Bearer <token>"

  if (!token) return res.status(401).json({ error: 'Falta token de autenticación (No Autorizado)' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido o expirado (Prohibido)' });
    req.user = user;
    next();
  });
}

// Middleware to ensure user is an administrator
function requireAdmin(req, res, next) {
  authenticateToken(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Se requieren permisos de Administrador para esta acción' });
    }
    next();
  });
}

// --- AUTHENTICATION ROUTES ---

// Public registration is DISABLED — only admin can create users
app.post('/api/auth/register', (req, res) => {
  res.status(403).json({ error: 'El registro público está desactivado. Contacta al Administrador.' });
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Debes completar el usuario y contraseña' });
  }

  try {
    const db = await getDbConnection();
    const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      await db.close();
      return res.status(400).json({ error: 'Credenciales inválidas' });
    }

    const userPayload = { 
      id: user.id, 
      username: user.username, 
      role: user.role,
      avatar: user.avatar,
      phone: user.phone,
      surgeries: user.surgeries,
      medical_conditions: user.medical_conditions,
      emergency_contact: user.emergency_contact,
      birth_date: user.birth_date,
      membership_plan_id: user.membership_plan_id,
      membership_start_date: user.membership_start_date,
      membership_end_date: user.membership_end_date,
      membership_status: user.membership_status
    };
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });

    await db.close();
    res.json({ user: userPayload, token });
  } catch (err) {
    res.status(500).json({ error: 'Error en el servidor al iniciar sesión', details: err.message });
  }
});

// Get Current User Profile
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const db = await getDbConnection();
    const user = await db.get('SELECT id, username, role, phone, surgeries, medical_conditions, emergency_contact, birth_date, avatar, membership_plan_id, membership_start_date, membership_end_date, membership_status FROM users WHERE id = ?', [req.user.id]);
    await db.close();
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener perfil', details: err.message });
  }
});

// Public Password Reset (Requires Username and Phone match for security)
app.post('/api/auth/reset', async (req, res) => {
  const { username, phone, newPassword } = req.body;
  if (!username || !phone || !newPassword) {
    return res.status(400).json({ error: 'Debes completar todos los campos de seguridad' });
  }

  try {
    const db = await getDbConnection();
    const user = await db.get('SELECT id FROM users WHERE username = ? AND phone = ?', [username, phone]);

    if (!user) {
      await db.close();
      return res.status(400).json({ error: 'Los datos no coinciden con ningún guerrero registrado' });
    }

    const newHash = bcrypt.hashSync(newPassword, 10);
    await db.run('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, user.id]);
    await db.close();

    res.json({ success: true, message: '¡Tu contraseña ha sido restaurada con éxito!' });
  } catch (err) {
    res.status(500).json({ error: 'Error al restaurar contraseña', details: err.message });
  }
});

// Update Current User Profile (Avatar)
app.put('/api/auth/me', authenticateToken, async (req, res) => {
  const { avatar } = req.body;
  try {
    const db = await getDbConnection();
    await db.run('UPDATE users SET avatar = ? WHERE id = ?', [avatar || null, req.user.id]);
    const user = await db.get('SELECT id, username, role, phone, surgeries, medical_conditions, emergency_contact, birth_date, avatar, membership_plan_id, membership_start_date, membership_end_date, membership_status FROM users WHERE id = ?', [req.user.id]);
    await db.close();
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: 'Error al actualizar perfil', details: err.message });
  }
});

// Change Current User Password
app.put('/api/auth/me/password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  }
  
  try {
    const db = await getDbConnection();
    const user = await db.get('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
    
    if (!user || !bcrypt.compareSync(currentPassword, user.password_hash)) {
      await db.close();
      return res.status(400).json({ error: 'La contraseña actual es incorrecta' });
    }
    
    const newHash = bcrypt.hashSync(newPassword, 10);
    await db.run('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, req.user.id]);
    await db.close();
    
    res.json({ success: true, message: 'Contraseña actualizada correctamente' });
  } catch (err) {
    res.status(500).json({ error: 'Error al actualizar contraseña', details: err.message });
  }
});


// --- ADMIN USER MANAGEMENT ROUTES ---

// List all users (Admin-only)
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const db = await getDbConnection();
    const rows = await db.all('SELECT id, username, role, phone, surgeries, medical_conditions, emergency_contact, birth_date, membership_plan_id, membership_start_date, membership_end_date, membership_status FROM users ORDER BY role DESC, username ASC');
    await db.close();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener usuarios', details: err.message });
  }
});

// Create user (Admin-only)
app.post('/api/admin/users', requireAdmin, async (req, res) => {
  const { username, password, role, phone, surgeries, medical_conditions, emergency_contact, birth_date, membership_plan_id, membership_start_date, membership_end_date, membership_status } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Nombre de usuario y contraseña son requeridos' });
  }

  try {
    const db = await getDbConnection();
    const existing = await db.get('SELECT * FROM users WHERE username = ?', [username]);
    if (existing) {
      await db.close();
      return res.status(400).json({ error: 'El nombre de usuario ya está registrado' });
    }

    const id = `user-${Date.now()}`;
    const passwordHash = bcrypt.hashSync(password, 10);
    const assignedRole = role === 'admin' ? 'admin' : 'user';

    let endStr = membership_end_date;
    if (membership_start_date && !membership_end_date) {
      const d = new Date(membership_start_date);
      d.setMonth(d.getMonth() + 1);
      endStr = d.toISOString().split('T')[0];
    }

    await db.run(
      'INSERT INTO users (id, username, password_hash, role, phone, surgeries, medical_conditions, emergency_contact, birth_date, membership_plan_id, membership_start_date, membership_end_date, membership_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [id, username, passwordHash, assignedRole, phone || null, surgeries || null, medical_conditions || null, emergency_contact || null, birth_date || null, membership_plan_id || null, membership_start_date || null, endStr || null, membership_status || 'none']
    );

    await db.close();
    res.status(201).json({ id, username, role: assignedRole, membership_plan_id, membership_start_date, membership_end_date, membership_status });
  } catch (err) {
    res.status(500).json({ error: 'Error al crear usuario', details: err.message });
  }
});

// Edit user (Admin-only)
app.put('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { username, password, role, phone, surgeries, medical_conditions, emergency_contact, birth_date, membership_plan_id, membership_start_date, membership_end_date, membership_status } = req.body;
  
  if (!username) {
    return res.status(400).json({ error: 'Nombre de usuario es requerido' });
  }

  try {
    const db = await getDbConnection();
    
    // Check if username already exists for a different user
    const existing = await db.get('SELECT id FROM users WHERE username = ? AND id != ?', [username, id]);
    if (existing) {
      await db.close();
      return res.status(400).json({ error: 'El nombre de usuario ya está en uso' });
    }

    let endStr = membership_end_date;
    if (membership_start_date && !membership_end_date) {
      const d = new Date(membership_start_date);
      d.setMonth(d.getMonth() + 1);
      endStr = d.toISOString().split('T')[0];
    }

    const assignedRole = role === 'admin' ? 'admin' : 'user';
    let query = 'UPDATE users SET username = ?, role = ?, phone = ?, surgeries = ?, medical_conditions = ?, emergency_contact = ?, birth_date = ?, membership_plan_id = ?, membership_start_date = ?, membership_end_date = ?, membership_status = ? WHERE id = ?';
    let params = [username, assignedRole, phone || null, surgeries || null, medical_conditions || null, emergency_contact || null, birth_date || null, membership_plan_id || null, membership_start_date || null, endStr || null, membership_status || 'none', id];

    if (password && password.trim() !== '') {
      const passwordHash = bcrypt.hashSync(password, 10);
      query = 'UPDATE users SET username = ?, password_hash = ?, role = ?, phone = ?, surgeries = ?, medical_conditions = ?, emergency_contact = ?, birth_date = ?, membership_plan_id = ?, membership_start_date = ?, membership_end_date = ?, membership_status = ? WHERE id = ?';
      params = [username, passwordHash, assignedRole, phone || null, surgeries || null, medical_conditions || null, emergency_contact || null, birth_date || null, membership_plan_id || null, membership_start_date || null, endStr || null, membership_status || 'none', id];
    }

    const result = await db.run(query, params);
    await db.close();
    
    if (result.changes === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    
    // Return updated user data (without password)
    res.json({ id, username, role: assignedRole, phone, surgeries, medical_conditions, emergency_contact, birth_date, membership_plan_id, membership_start_date, membership_end_date, membership_status });
  } catch (err) {
    res.status(500).json({ error: 'Error al actualizar usuario', details: err.message });
  }
});

// Delete user (Admin-only)
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  // Prevent deleting the main admin account
  if (id === '1' || id === 1) return res.status(403).json({ error: 'No se puede eliminar al Administrador principal' });
  
  try {
    const db = await getDbConnection();
    const result = await db.run('DELETE FROM users WHERE id = ?', [id]);
    await db.close();
    if (result.changes === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Error al eliminar usuario', details: err.message });
  }
});

// Reset User Password (Admin-only)
app.post('/api/admin/users/:id/reset-password', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const defaultPassword = 'valhalla2026';
    const newHash = bcrypt.hashSync(defaultPassword, 10);
    
    const db = await getDbConnection();
    const result = await db.run('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, id]);
    await db.close();
    
    if (result.changes === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    
    res.json({ success: true, message: `Contraseña restablecida a: ${defaultPassword}` });
  } catch (err) {
    res.status(500).json({ error: 'Error al restablecer contraseña', details: err.message });
  }
});





// --- MEASUREMENTS ROUTES ---

// Get measurements — admin gets all (optionally filtered by user_id), user gets their own
app.get('/api/measurements', authenticateToken, async (req, res) => {
  try {
    const db = await getDbConnection();
    let rows;
    if (req.user.role === 'admin') {
      const { user_id } = req.query;
      if (user_id) {
        rows = await db.all('SELECT * FROM measurements WHERE user_id = ? ORDER BY date DESC', [user_id]);
      } else {
        rows = await db.all('SELECT * FROM measurements ORDER BY date DESC');
      }
    } else {
      rows = await db.all('SELECT * FROM measurements WHERE user_id = ? ORDER BY date DESC', [req.user.id]);
    }
    await db.close();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener medidas', details: err.message });
  }
});

// Add measurement record (Admin-only)
app.post('/api/measurements', requireAdmin, async (req, res) => {
  const {
    user_id, username, date,
    gender, age,
    weight, height, body_fat,
    neck, shoulders, chest, waist, hips,
    biceps_left, biceps_right,
    thighs_left, thighs_right,
    calves_left, calves_right,
    systolic, diastolic, resting_hr,
    goal, energy_level, sleep_hours,
    daily_calories, daily_protein,
    notes
  } = req.body;

  if (!user_id || !username) {
    return res.status(400).json({ error: 'user_id y username son requeridos' });
  }

  try {
    const db = await getDbConnection();
    const id = `meas-${Date.now()}`;
    const dateStr = date || new Date().toISOString();

    const toNum = (v) => (v !== undefined && v !== '' ? parseFloat(v) : null);
    const toInt = (v) => (v !== undefined && v !== '' ? parseInt(v) : null);

    await db.run(
      `INSERT INTO measurements
        (id, user_id, username, date,
         gender, age,
         weight, height, body_fat,
         neck, shoulders, chest, waist, hips,
         biceps_left, biceps_right, thighs_left, thighs_right, calves_left, calves_right,
         systolic, diastolic, resting_hr,
         goal, energy_level, sleep_hours, daily_calories, daily_protein,
         notes)
       VALUES (?,?,?,?, ?,?, ?,?,?, ?,?,?,?,?, ?,?,?,?,?,?, ?,?,?, ?,?,?,?,?, ?)`,
      [id, user_id, username, dateStr,
        gender || null, toInt(age),
        toNum(weight), toNum(height), toNum(body_fat),
        toNum(neck), toNum(shoulders), toNum(chest), toNum(waist), toNum(hips),
        toNum(biceps_left), toNum(biceps_right), toNum(thighs_left), toNum(thighs_right), toNum(calves_left), toNum(calves_right),
        toInt(systolic), toInt(diastolic), toInt(resting_hr),
        goal || null, toInt(energy_level), toNum(sleep_hours), toInt(daily_calories), toInt(daily_protein),
        notes || null]
    );

    const saved = await db.get('SELECT * FROM measurements WHERE id = ?', [id]);
    await db.close();
    res.status(201).json(saved);
  } catch (err) {
    res.status(500).json({ error: 'Error al guardar medidas', details: err.message });
  }
});

// Delete measurement record (Admin-only)
app.delete('/api/measurements/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const db = await getDbConnection();
    const result = await db.run('DELETE FROM measurements WHERE id = ?', [id]);
    await db.close();
    if (result.changes === 0) return res.status(404).json({ error: 'Registro no encontrado' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Error al eliminar medida', details: err.message });
  }
});


// List Products

app.get('/api/products', async (req, res) => {
  try {
    const db = await getDbConnection();
    const rows = await db.all('SELECT * FROM products');
    await db.close();

    const formatted = rows.map(r => ({
      ...r,
      features: JSON.parse(r.features || '[]')
    }));
    res.json(formatted);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener productos', details: err.message });
  }
});

// Create Product (Admin-only)
app.post('/api/products', requireAdmin, async (req, res) => {
  const { name, price, category, description, features, image } = req.body;
  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Nombre, precio y categoría son requeridos' });
  }

  try {
    const db = await getDbConnection();
    const id = `prod-${Date.now()}`;
    const featsStr = JSON.stringify(Array.isArray(features) ? features : []);

    await db.run(
      `INSERT INTO products (id, name, price, category, rating, reviews, description, features, image) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, name, parseFloat(price), category, 5.0, 10, description || '', featsStr, image || null]
    );

    const newProduct = { id, name, price: parseFloat(price), category, rating: 5.0, reviews: 10, description, features: Array.isArray(features) ? features : [], image };
    await db.close();
    res.status(201).json(newProduct);
  } catch (err) {
    res.status(500).json({ error: 'Error al crear producto', details: err.message });
  }
});

// Update Product (Admin-only)
app.put('/api/products/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, price, category, description, features, image } = req.body;

  try {
    const db = await getDbConnection();
    const existing = await db.get('SELECT * FROM products WHERE id = ?', [id]);
    if (!existing) {
      await db.close();
      return res.status(404).json({ error: 'Producto no encontrado' });
    }

    const featsStr = JSON.stringify(Array.isArray(features) ? features : []);

    await db.run(
      `UPDATE products 
       SET name = ?, price = ?, category = ?, description = ?, features = ?, image = ? 
       WHERE id = ?`,
      [name || existing.name, parseFloat(price) || existing.price, category || existing.category, description || existing.description, featsStr, image !== undefined ? image : existing.image, id]
    );

    await db.close();
    res.json({ id, name, price: parseFloat(price), category, description, features, image: image !== undefined ? image : existing.image });
  } catch (err) {
    res.status(500).json({ error: 'Error al actualizar producto', details: err.message });
  }
});

// Delete Product (Admin-only)
app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const db = await getDbConnection();
    const result = await db.run('DELETE FROM products WHERE id = ?', [id]);
    await db.close();

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }
    res.json({ success: true, message: 'Producto eliminado de la armería' });
  } catch (err) {
    res.status(500).json({ error: 'Error al eliminar producto', details: err.message });
  }
});


// --- PLANS ROUTES (CRUD) ---

// List Plans
app.get('/api/plans', async (req, res) => {
  try {
    const db = await getDbConnection();
    const rows = await db.all('SELECT * FROM plans');
    await db.close();

    const formatted = rows.map(r => ({
      ...r,
      goals: JSON.parse(r.goals || '[]')
    }));
    res.json(formatted);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener planes', details: err.message });
  }
});

// Create Plan (Admin-only)
app.post('/api/plans', requireAdmin, async (req, res) => {
  const { name, description, price, icon, goals, bestFor } = req.body;
  if (!name || !price) {
    return res.status(400).json({ error: 'Nombre y precio son requeridos' });
  }

  try {
    const db = await getDbConnection();
    const id = `plan-${Date.now()}`;
    const goalsStr = JSON.stringify(Array.isArray(goals) ? goals : []);

    await db.run(
      `INSERT INTO plans (id, name, description, price, icon, goals, bestFor) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [id, name, description || '', parseFloat(price), icon || 'ᚢ', goalsStr, bestFor || 'strength']
    );

    const newPlan = { id, name, description, price: parseFloat(price), icon, goals: Array.isArray(goals) ? goals : [], bestFor };
    await db.close();
    res.status(201).json(newPlan);
  } catch (err) {
    res.status(500).json({ error: 'Error al crear plan', details: err.message });
  }
});

// Update Plan (Admin-only)
app.put('/api/plans/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, description, price, icon, goals, bestFor } = req.body;

  try {
    const db = await getDbConnection();
    const existing = await db.get('SELECT * FROM plans WHERE id = ?', [id]);
    if (!existing) {
      await db.close();
      return res.status(404).json({ error: 'Plan no encontrado' });
    }

    const goalsStr = JSON.stringify(Array.isArray(goals) ? goals : []);

    await db.run(
      `UPDATE plans 
       SET name = ?, description = ?, price = ?, icon = ?, goals = ?, bestFor = ? 
       WHERE id = ?`,
      [name || existing.name, description || existing.description, parseFloat(price) || existing.price, icon || existing.icon, goalsStr, bestFor || existing.bestFor, id]
    );

    await db.close();
    res.json({ id, name, description, price: parseFloat(price), icon, goals, bestFor });
  } catch (err) {
    res.status(500).json({ error: 'Error al actualizar plan', details: err.message });
  }
});

// Delete Plan (Admin-only)
app.delete('/api/plans/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const db = await getDbConnection();
    const result = await db.run('DELETE FROM plans WHERE id = ?', [id]);
    await db.close();

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Plan no encontrado' });
    }
    res.json({ success: true, message: 'Plan eliminado' });
  } catch (err) {
    res.status(500).json({ error: 'Error al eliminar plan', details: err.message });
  }
});


// --- FEATURES ROUTES (CRUD) ---

// List Features (Gym Areas)
app.get('/api/features', async (req, res) => {
  try {
    const db = await getDbConnection();
    const rows = await db.all('SELECT * FROM features');
    await db.close();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener áreas del gimnasio', details: err.message });
  }
});

// Create Feature (Admin-only)
app.post('/api/features', requireAdmin, async (req, res) => {
  const { title, area, icon, desc } = req.body;
  if (!title || !area) {
    return res.status(400).json({ error: 'Título y área son requeridos' });
  }

  try {
    const db = await getDbConnection();
    const id = `feat-${Date.now()}`;

    await db.run(
      `INSERT INTO features (id, title, area, icon, desc) 
       VALUES (?, ?, ?, ?, ?)`,
      [id, title, area, icon || '🛡️', desc || '']
    );

    const newFeature = { id, title, area, icon, desc };
    await db.close();
    res.status(201).json(newFeature);
  } catch (err) {
    res.status(500).json({ error: 'Error al crear área del gimnasio', details: err.message });
  }
});

// Update Feature (Admin-only)
app.put('/api/features/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { title, area, icon, desc } = req.body;

  try {
    const db = await getDbConnection();
    const existing = await db.get('SELECT * FROM features WHERE id = ?', [id]);
    if (!existing) {
      await db.close();
      return res.status(404).json({ error: 'Área no encontrada' });
    }

    await db.run(
      `UPDATE features 
       SET title = ?, area = ?, icon = ?, desc = ? 
       WHERE id = ?`,
      [title || existing.title, area || existing.area, icon || existing.icon, desc || existing.desc, id]
    );

    await db.close();
    res.json({ id, title, area, icon, desc });
  } catch (err) {
    res.status(500).json({ error: 'Error al actualizar área del gimnasio', details: err.message });
  }
});

// Delete Feature (Admin-only)
app.delete('/api/features/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const db = await getDbConnection();
    const result = await db.run('DELETE FROM features WHERE id = ?', [id]);
    await db.close();

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Área no encontrada' });
    }
    res.json({ success: true, message: 'Área eliminada del templo' });
  } catch (err) {
    res.status(500).json({ error: 'Error al eliminar área del gimnasio', details: err.message });
  }
});

// --- ORDERS ROUTES (CRUD) ---

// List Orders (Auth required: Admin gets all, User gets only their own)
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const db = await getDbConnection();
    let rows = [];
    if (req.user.role === 'admin') {
      rows = await db.all('SELECT * FROM orders ORDER BY date DESC');
    } else {
      rows = await db.all('SELECT * FROM orders WHERE user_id = ? ORDER BY date DESC', [req.user.id]);
    }
    await db.close();

    const formatted = rows.map(r => ({
      ...r,
      products: JSON.parse(r.products || '[]'),
      order_type: r.order_type || 'store'
    }));
    res.json(formatted);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener órdenes', details: err.message });
  }
});

// Create Order (Auth required)
app.post('/api/orders', authenticateToken, async (req, res) => {
  const { products, total, phone, address, order_type } = req.body;
  const oType = order_type || 'store';
  
  if (!products || !total) {
    return res.status(400).json({ error: 'Faltan datos de la orden (productos, total)' });
  }
  if (oType === 'store' && (!phone || !address)) {
    return res.status(400).json({ error: 'Faltan datos de envío para pedido de tienda' });
  }

  try {
    const db = await getDbConnection();
    const id = `ord-${Date.now()}`;
    const prodStr = JSON.stringify(products);
    const dateStr = new Date().toISOString();
    const status = 'pending';

    await db.run(
      `INSERT INTO orders (id, user_id, username, products, total, phone, address, status, date, order_type) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, req.user.id, req.user.username, prodStr, parseFloat(total), phone || '', address || '', status, dateStr, oType]
    );

    const newOrder = { 
      id, 
      user_id: req.user.id, 
      username: req.user.username, 
      products, 
      total: parseFloat(total), 
      phone: phone || '', 
      address: address || '', 
      status, 
      date: dateStr,
      order_type: oType
    };
    await db.close();
    res.status(201).json(newOrder);
  } catch (err) {
    res.status(500).json({ error: 'Error al crear orden', details: err.message });
  }
});

// Update Order Status (Admin-only)
app.put('/api/orders/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!status) return res.status(400).json({ error: 'Estado de la orden es requerido' });

  try {
    const db = await getDbConnection();
    const result = await db.run('UPDATE orders SET status = ? WHERE id = ?', [status, id]);
    await db.close();

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Orden no encontrada' });
    }
    res.json({ id, status });
  } catch (err) {
    res.status(500).json({ error: 'Error al actualizar estado de la orden', details: err.message });
  }
});

// Delete Order (Admin-only)
app.delete('/api/orders/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const db = await getDbConnection();
    const result = await db.run('DELETE FROM orders WHERE id = ?', [id]);
    await db.close();

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Orden no encontrada' });
    }
    res.json({ success: true, message: 'Orden eliminada' });
  } catch (err) {
    res.status(500).json({ error: 'Error al eliminar orden', details: err.message });
  }
});

// --- PAYMENTS & FINANCE ROUTES ---

// List all payments (Admin-only)
app.get('/api/admin/payments', requireAdmin, async (req, res) => {
  try {
    const db = await getDbConnection();
    const rows = await db.all('SELECT * FROM payments ORDER BY payment_date DESC');
    await db.close();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener pagos', details: err.message });
  }
});

// Register payment and update user membership (Admin-only)
app.post('/api/admin/payments', requireAdmin, async (req, res) => {
  const { user_id, username, plan_id, plan_name, amount, payment_date, notes } = req.body;
  if (!user_id || !username || !amount || !payment_date) {
    return res.status(400).json({ error: 'Faltan datos obligatorios para registrar el pago' });
  }

  try {
    const db = await getDbConnection();
    const id = `pay-${Date.now()}`;
    
    // Calculate membership end date (+1 exact month from payment_date to keep the same day of the month)
    const start = new Date(payment_date);
    start.setMonth(start.getMonth() + 1);
    const endStr = start.toISOString().split('T')[0];

    // Insert payment record
    await db.run(
      'INSERT INTO payments (id, user_id, username, plan_id, plan_name, amount, payment_date, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [id, user_id, username, plan_id || null, plan_name || 'Membresía', parseFloat(amount), payment_date, notes || '']
    );

    // Update user membership details (extend end date but DO NOT overwrite original start date)
    await db.run(
      'UPDATE users SET membership_plan_id = ?, membership_end_date = ?, membership_status = ? WHERE id = ?',
      [plan_id || null, endStr, 'active', user_id]
    );

    await db.close();
    res.status(201).json({ id, user_id, username, plan_id, plan_name, amount: parseFloat(amount), payment_date, notes, membership_end_date: endStr });
  } catch (err) {
    res.status(500).json({ error: 'Error al registrar el pago', details: err.message });
  }
});

// Delete payment record (Admin-only)
app.delete('/api/admin/payments/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const db = await getDbConnection();
    const result = await db.run('DELETE FROM payments WHERE id = ?', [id]);
    await db.close();
    if (result.changes === 0) return res.status(404).json({ error: 'Pago no encontrado' });
    res.json({ success: true, message: 'Registro de pago eliminado' });
  } catch (err) {
    res.status(500).json({ error: 'Error al eliminar pago', details: err.message });
  }
});


// --- USER NOTIFICATIONS ROUTES ---

// Get current user notifications
app.get('/api/notifications/my', authenticateToken, async (req, res) => {
  try {
    const db = await getDbConnection();
    const rows = await db.all('SELECT * FROM notifications WHERE user_id = ? ORDER BY date DESC LIMIT 50', [req.user.id]);
    await db.close();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener notificaciones', details: err.message });
  }
});

// Mark notification as read
app.post('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const db = await getDbConnection();
    await db.run('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?', [id, req.user.id]);
    await db.close();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Error al marcar notificación como leída', details: err.message });
  }
});


// --- MEMBERSHIPS SCANNERS & WARNINGS (WhatsApp & Panel) ---
async function scanAndNotifyMemberships() {
  console.log('🛡️  Ejecutando escaneo automático de membresías...');
  try {
    const db = await getDbConnection();
    
    // Scan active memberships to check warnings or mark expired
    const users = await db.all("SELECT id, username, phone, membership_end_date, membership_status FROM users WHERE membership_status = 'active' OR membership_status = 'expired'");
    
    // We get current date without time zone issues (local midnights)
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    for (const user of users) {
      if (!user.membership_end_date) continue;
      
      const endDate = new Date(user.membership_end_date);
      endDate.setHours(0, 0, 0, 0);

      const diffTime = endDate.getTime() - today.getTime();
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

      // 1. If membership expired and it was marked active, update to 'expired'
      if (diffDays < 0 && user.membership_status === 'active') {
        await db.run("UPDATE users SET membership_status = 'expired' WHERE id = ?", [user.id]);
        console.log(`❌ Membresía del guerrero ${user.username} ha expirado el ${user.membership_end_date}.`);
        continue;
      }

      // 2. If exactly 3 days left (or between 0 and 3 days left), send warning if not already warned
      if (diffDays >= 0 && diffDays <= 3) {
        const notifMsg = `Estimado(a) Guerrero(a) ${user.username}, tu mensualidad de Valhalla Gym vence en ${diffDays === 0 ? 'hoy' : diffDays + ' día(s)'} (${user.membership_end_date}). Evita la interrupción de tu entrenamiento.`;
        
        // Avoid duplicate notifications for the same end date
        const alreadyNotified = await db.get(
          "SELECT id FROM notifications WHERE user_id = ? AND type = 'expiration_warning' AND message LIKE ?",
          [user.id, `%${user.membership_end_date}%`]
        );

        if (!alreadyNotified) {
          const notifId = `notif-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;
          // Create in-app notification
          await db.run(
            'INSERT INTO notifications (id, user_id, message, type, date, is_read) VALUES (?, ?, ?, ?, ?, 0)',
            [notifId, user.id, notifMsg, 'expiration_warning', new Date().toISOString()]
          );
          
          // Send simulated WhatsApp (print to server logs)
          console.log(`\n--- ENVÍO AUTOMÁTICO WHATSAPP DE EXPIRACIÓN ---`);
          console.log(`Guerrero: ${user.username}`);
          console.log(`Teléfono: ${user.phone || 'No registrado'}`);
          console.log(`Mensaje: ${notifMsg}`);
          console.log(`-----------------------------------------------\n`);
        }
      }
    }
    await db.close();
  } catch (err) {
    console.error('Error durante escaneo de membresías:', err);
  }
}

// Run scanner on startup after 5 seconds
setTimeout(scanAndNotifyMemberships, 5000);
// Run scanner every 12 hours
setInterval(scanAndNotifyMemberships, 12 * 60 * 60 * 1000);


// Serve static assets from frontend build
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ error: 'Endpoint not found' });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`⚔️  Valhalla Gym Backend running on port ${PORT}`);
});
