import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcryptjs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = process.env.DATABASE_PATH
  ? path.resolve(process.env.DATABASE_PATH)
  : path.resolve(__dirname, 'valhalla.sqlite');

export async function getDbConnection() {
  return open({
    filename: dbPath,
    driver: sqlite3.Database
  });
}

export async function initDb() {
  const db = await getDbConnection();

  // Create tables if they don't exist
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE,
      password_hash TEXT,
      role TEXT,
      phone TEXT,
      surgeries TEXT,
      medical_conditions TEXT,
      emergency_contact TEXT,
      birth_date TEXT,
      membership_plan_id TEXT,
      membership_start_date TEXT,
      membership_end_date TEXT,
      membership_status TEXT DEFAULT 'none',
      avatar TEXT
    );

    CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      name TEXT,
      price REAL,
      category TEXT,
      rating REAL,
      reviews INTEGER,
      description TEXT,
      features TEXT,
      image TEXT
    );

    CREATE TABLE IF NOT EXISTS plans (
      id TEXT PRIMARY KEY,
      name TEXT,
      description TEXT,
      price REAL,
      icon TEXT,
      goals TEXT,
      bestFor TEXT
    );

    CREATE TABLE IF NOT EXISTS features (
      id TEXT PRIMARY KEY,
      title TEXT,
      area TEXT,
      icon TEXT,
      desc TEXT
    );

    CREATE TABLE IF NOT EXISTS orders (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      username TEXT,
      products TEXT,
      total REAL,
      phone TEXT,
      address TEXT,
      status TEXT,
      date TEXT,
      order_type TEXT DEFAULT 'store'
    );

    CREATE TABLE IF NOT EXISTS measurements (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      date TEXT NOT NULL,
      -- General
      gender TEXT,
      age INTEGER,
      weight REAL,
      height REAL,
      body_fat REAL,
      -- Circumferences (cm)
      neck REAL,
      shoulders REAL,
      chest REAL,
      waist REAL,
      hips REAL,
      biceps_left REAL,
      biceps_right REAL,
      thighs_left REAL,
      thighs_right REAL,
      calves_left REAL,
      calves_right REAL,
      -- Cardiovascular
      systolic INTEGER,
      diastolic INTEGER,
      resting_hr INTEGER,
      -- Lifestyle & Training
      goal TEXT,
      energy_level INTEGER,
      sleep_hours REAL,
      daily_calories INTEGER,
      daily_protein INTEGER,
      notes TEXT
    );

    CREATE TABLE IF NOT EXISTS payments (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      username TEXT,
      plan_id TEXT,
      plan_name TEXT,
      amount REAL,
      payment_date TEXT,
      notes TEXT
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      message TEXT,
      type TEXT,
      date TEXT,
      is_read INTEGER DEFAULT 0
    );
  `);

  // Migrate existing measurements table: add new columns if they don't exist yet
  const measNewCols = [
    'ALTER TABLE measurements ADD COLUMN gender TEXT',
    'ALTER TABLE measurements ADD COLUMN age INTEGER',
    'ALTER TABLE measurements ADD COLUMN systolic INTEGER',
    'ALTER TABLE measurements ADD COLUMN diastolic INTEGER',
    'ALTER TABLE measurements ADD COLUMN resting_hr INTEGER',
    'ALTER TABLE measurements ADD COLUMN goal TEXT',
    'ALTER TABLE measurements ADD COLUMN energy_level INTEGER',
    'ALTER TABLE measurements ADD COLUMN sleep_hours REAL',
    'ALTER TABLE measurements ADD COLUMN daily_calories INTEGER',
    'ALTER TABLE measurements ADD COLUMN daily_protein INTEGER',
  ];
  for (const sql of measNewCols) {
    try { await db.run(sql); } catch (_) { /* column already exists */ }
  }

  // Migrate existing users table: add medical and membership columns
  const usersNewCols = [
    'ALTER TABLE users ADD COLUMN phone TEXT',
    'ALTER TABLE users ADD COLUMN surgeries TEXT',
    'ALTER TABLE users ADD COLUMN medical_conditions TEXT',
    'ALTER TABLE users ADD COLUMN emergency_contact TEXT',
    'ALTER TABLE users ADD COLUMN birth_date TEXT',
    'ALTER TABLE users ADD COLUMN avatar TEXT',
    'ALTER TABLE users ADD COLUMN membership_plan_id TEXT',
    'ALTER TABLE users ADD COLUMN membership_start_date TEXT',
    'ALTER TABLE users ADD COLUMN membership_end_date TEXT',
    'ALTER TABLE users ADD COLUMN membership_status TEXT DEFAULT \'none\''
  ];
  for (const sql of usersNewCols) {
    try { await db.run(sql); } catch (_) { /* column already exists */ }
  }

  // Migrate existing products table: add image column
  try {
    await db.run('ALTER TABLE products ADD COLUMN image TEXT');
  } catch (_) { /* column already exists */ }

  // Migrate existing orders table: add order_type column
  try {
    await db.run("ALTER TABLE orders ADD COLUMN order_type TEXT DEFAULT 'store'");
  } catch (_) { /* column already exists */ }

  // Seed default admin and user if users table is empty
  const userCount = await db.get('SELECT COUNT(*) as count FROM users');
  if (userCount.count === 0) {
    const adminHash = bcrypt.hashSync('admin', 10);
    const userHash = bcrypt.hashSync('ragnar', 10);

    await db.run(
      'INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)',
      ['user-admin', 'admin', adminHash, 'admin']
    );
    await db.run(
      'INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)',
      ['user-ragnar', 'ragnar', userHash, 'user']
    );
    console.log('Seeded default users (admin/admin, ragnar/ragnar).');
  }

  // Seed default products if empty
  const prodCount = await db.get('SELECT COUNT(*) as count FROM products');
  if (prodCount.count === 0) {
    const defaultProducts = [
      {
        id: 'prod-1',
        name: 'Elixir de Odín (Pre-Workout)',
        price: 34.99,
        category: 'supplements',
        rating: 4.9,
        reviews: 142,
        description: 'Fórmula legendaria de enfoque y poder salvaje. Siente la fuerza del Padre de Todo en cada repetición.',
        features: JSON.stringify(['300mg Cafeína anhidra', '6g L-Citrulina', 'Enfoque mental rúnico'])
      },
      {
        id: 'prod-2',
        name: 'Shaker de Mjölnir (Acero Inox)',
        price: 24.99,
        category: 'gear',
        rating: 4.8,
        reviews: 98,
        description: 'Shaker térmico de alta resistencia fabricado en acero inoxidable con runes grabadas. Irrompible.',
        features: JSON.stringify(['Doble pared al vacío', '750ml de capacidad', 'Antiderrames sellado rúnico'])
      },
      {
        id: 'prod-3',
        name: 'Camiseta "Clan Valhalla"',
        price: 19.99,
        category: 'apparel',
        rating: 5.0,
        reviews: 215,
        description: 'Algodón premium ultra suave con corte atlético y logo desgastado del gimnasio en verde rúnico.',
        features: JSON.stringify(['100% Algodón peinado', 'Corte ajustado en hombros', 'Transpirable y resistente'])
      },
      {
        id: 'prod-4',
        name: 'Cinturón de Fuerza "Asgard"',
        price: 49.99,
        category: 'gear',
        rating: 4.9,
        reviews: 84,
        description: 'Cinturón de levantamiento de 10mm de grosor en cuero genuino curtido. Soporte inquebrantable.',
        features: JSON.stringify(['Hebilla de acero reforzada', 'Cuero de 4 capas', 'Soporte lumbar óptimo'])
      },
      {
        id: 'prod-5',
        name: 'Sangre de Gigante (Creatina HCL)',
        price: 29.99,
        category: 'supplements',
        rating: 4.7,
        reviews: 110,
        description: 'Creatina de máxima pureza para fuerza explosiva y recuperación digna de un guerrero Jotunn.',
        features: JSON.stringify(['Creatina HCL ultra-soluble', '120 porciones', 'Cero retención de líquidos'])
      },
      {
        id: 'prod-6',
        name: 'Correas de Agarre "Fenrir"',
        price: 12.99,
        category: 'gear',
        rating: 4.8,
        reviews: 67,
        description: 'Straps acolchados de alta tracción para peso muerto. Un agarre tan fuerte que ni las cadenas de los dioses romperían.',
        features: JSON.stringify(['Algodón trenzado reforzado', 'Acolchado de neopreno', 'Largo olímpico de 60cm'])
      }
    ];

    for (const prod of defaultProducts) {
      await db.run(
        `INSERT INTO products (id, name, price, category, rating, reviews, description, features) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [prod.id, prod.name, prod.price, prod.category, prod.rating, prod.reviews, prod.description, prod.features]
      );
    }
    console.log('Seeded default products.');
  }

  // Seed default plans if empty
  const planCount = await db.get('SELECT COUNT(*) as count FROM plans');
  if (planCount.count === 0) {
    const defaultPlans = [
      {
        id: 'plan-berserker',
        name: 'Plan Berserker (Fuerza)',
        description: 'Enfocado en hipertrofia masiva y fuerza bruta. Conviértete en una fuerza de la naturaleza.',
        price: 39.99,
        icon: 'ᚢ',
        goals: JSON.stringify(['Aumento de masa muscular', 'Poder y fuerza máxima', 'Rutinas intensas de pesas']),
        bestFor: 'strength'
      },
      {
        id: 'plan-valkyrie',
        name: 'Acondicionamiento Valkyria',
        description: 'Resistencia cardiovascular, definición extrema y agilidad funcional. Vuela sobre tus límites.',
        price: 34.99,
        icon: 'ᛖ',
        goals: JSON.stringify(['Definición muscular magra', 'Resistencia aeróbica / HIIT', 'Agilidad y movilidad rápida']),
        bestFor: 'conditioning'
      },
      {
        id: 'plan-odin',
        name: 'El Consejo de Odín (1-on-1)',
        description: 'Asesoría premium de élite. Plan de nutrición estricto, rutinas dinámicas y check-ins diarios.',
        price: 69.99,
        icon: 'ᚨ',
        goals: JSON.stringify(['Coaching ilimitado diario', 'Plan nutricional flexible adaptativo', 'Monitoreo técnico de levantamientos']),
        bestFor: 'premium'
      }
    ];

    for (const plan of defaultPlans) {
      await db.run(
        `INSERT INTO plans (id, name, description, price, icon, goals, bestFor) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [plan.id, plan.name, plan.description, plan.price, plan.icon, plan.goals, plan.bestFor]
      );
    }
    console.log('Seeded default plans.');
  }

  // Seed default features if empty
  const featCount = await db.get('SELECT COUNT(*) as count FROM features');
  if (featCount.count === 0) {
    const defaultFeatures = [
      {
        id: 'feat-shield',
        title: 'La Muralla de Escudos',
        area: 'Zona de Peso Libre',
        icon: '🛡️',
        desc: 'Mancuernas de alta densidad, barras olímpicas y discos de hierro fundido para levantar pesado y forjar tu armadura muscular sin rodeos.'
      },
      {
        id: 'feat-hammer',
        title: 'El Martillo de Thor',
        area: 'Máquinas de Fuerza',
        icon: '🔨',
        desc: 'Sistemas de poleas convergentes y máquinas biomecánicas premium reguladas para aislar y maximizar la contracción de tus fibras.'
      },
      {
        id: 'feat-drakkar',
        title: 'El Drakkar',
        area: 'Cardio y Resistencia',
        icon: '⛵',
        desc: 'Remadoras de agua, cintas mecánicas curvas y Assault Bikes para desarrollar un acondicionamiento cardiovascular insaciable.'
      },
      {
        id: 'feat-jotunn',
        title: 'La Arena Jotunn',
        area: 'Powerlifting / Funcional',
        icon: '🏋️',
        desc: 'Plataformas profesionales de madera y caucho, jaulas de sentadillas monolíticas y barras de especialidad para romper tus récords.'
      }
    ];

    for (const feat of defaultFeatures) {
      await db.run(
        `INSERT INTO features (id, title, area, icon, desc) 
         VALUES (?, ?, ?, ?, ?)`,
        [feat.id, feat.title, feat.area, feat.icon, feat.desc]
      );
    }
    console.log('Seeded default features.');
  }

  await db.close();
}
