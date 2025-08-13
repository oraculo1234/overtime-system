FROM node:20-alpine
WORKDIR /app

# Instala dependencias sin lockfile
COPY package*.json ./
RUN npm install --omit=dev

# Copia el resto del código
COPY . .

ENV NODE_ENV=production
EXPOSE 3000

# Inicializa la DB (crea el admin) y arranca el server
CMD sh -c "node scripts/init_db.js || true; node server.js"
