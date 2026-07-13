# ⚔️ Valhalla Gym — Backend (API)

Servidor Express.js con base de datos SQLite. Maneja autenticación JWT, productos, planes, áreas del gimnasio y órdenes.

## Requisitos

- Node.js 18+

## Instalación

```bash
npm install
```

## Variables de Entorno

Copia `.env.example` a `.env` y configura:

```bash
cp .env.example .env
```

| Variable | Descripción | Default |
|---|---|---|
| `PORT` | Puerto del servidor | `5000` |
| `JWT_SECRET` | Clave secreta para JWT | `valhalla_mystic_key_12345` |
| `CORS_ORIGIN` | Orígenes permitidos (separados por coma) | `http://localhost:5173` |

## Desarrollo Local

```bash
npm run dev
```

## Producción

```bash
npm start
```

## Despliegue (Render / Railway)

1. Conecta tu repositorio
2. Configura el **Root Directory** a `backend`
3. **Build Command**: `npm install`
4. **Start Command**: `npm start`
5. Configura las variables de entorno:
   - `JWT_SECRET` → una clave segura
   - `CORS_ORIGIN` → la URL de tu frontend desplegado (ej: `https://valhalla-gym.vercel.app`)

## Usuarios por defecto

| Usuario | Contraseña | Rol |
|---|---|---|
| `admin` | `admin` | Administrador |
| `ragnar` | `ragnar` | Usuario |

## Endpoints

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| POST | `/api/auth/register` | — | Registrar usuario |
| POST | `/api/auth/login` | — | Iniciar sesión |
| GET | `/api/auth/me` | Token | Perfil actual |
| GET | `/api/products` | — | Listar productos |
| POST | `/api/products` | Admin | Crear producto |
| PUT | `/api/products/:id` | Admin | Editar producto |
| DELETE | `/api/products/:id` | Admin | Eliminar producto |
| GET | `/api/plans` | — | Listar planes |
| POST | `/api/plans` | Admin | Crear plan |
| PUT | `/api/plans/:id` | Admin | Editar plan |
| DELETE | `/api/plans/:id` | Admin | Eliminar plan |
| GET | `/api/features` | — | Listar áreas |
| POST | `/api/features` | Admin | Crear área |
| PUT | `/api/features/:id` | Admin | Editar área |
| DELETE | `/api/features/:id` | Admin | Eliminar área |
| GET | `/api/orders` | Token | Listar órdenes |
| POST | `/api/orders` | Token | Crear orden |
| PUT | `/api/orders/:id` | Admin | Actualizar estado |
| DELETE | `/api/orders/:id` | Admin | Eliminar orden |
