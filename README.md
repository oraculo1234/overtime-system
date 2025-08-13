# Overtime System (Node + Express + SQLite)

MVP para control de horas y horas extra (> 8h diarias). Incluye login con roles (admin/usuario).

## Requisitos
- Node 18+

## Desarrollo local
```bash
npm ci
cp .env.example .env  # actualiza JWT_SECRET
npm run init:db       # crea DB y admin
npm run dev           # http://localhost:3000
```
Admin por defecto: **admin@foragro.local / Admin123*!** (cámbialo).

## Deploy rápido

### Render.com (recomendado free)
1. Crea un repo en GitHub con estos archivos o usa el ZIP.
2. En Render: **New +** → **Blueprint** → elige el repo.
3. Render detecta `render.yaml`. Ajusta variables si quieres.
4. Espera el deploy y abre la URL pública.

### Railway.app
1. Sube el repo a GitHub.
2. Crea un proyecto en Railway → Deploy from Repo.
3. Añade variable `JWT_SECRET` (valor largo), Railway setea `PORT`.
4. Primer deploy ejecuta `npm run init:db` (en build).

### Docker (cualquier VPS)
```bash
docker build -t overtime-system .
docker run -p 3000:3000 --env JWT_SECRET=tu_secreto overtime-system
```

## Endpoints clave
- POST `/api/auth/login` {email, password}
- POST `/api/shifts/clock-in`
- POST `/api/shifts/clock-out`
- GET  `/api/shifts/my?from=&to=`
- Admin: GET `/api/users`, POST `/api/users`, POST `/api/auth/reset-password`

## Notas
- La DB `overtime.db` vive en disco. En Render/Railway free, al redeploy se reinicia. Para persistencia real usa Postgres.
- Tiempos en ISO/UTC. Puedes ajustar a tu zona en el frontend.
