const express = require('express');
const cors = require('cors');
const axios = require('axios');
const jwt = require('jwt-simple');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(cors());

const DB_PATH = './investigations.json';
const JWT_SECRET = process.env.JWT_SECRET || 'tu-secreto-aqui-cambiar';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;

const ALLOWED_ROLE = '1536562568565624851';
const EDIT_ROLE = '1536562569597427827';
const YOUR_GUILD_ID = process.env.GUILD_ID; // ID del servidor Discord

function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    }
  } catch (e) {
    console.log('Error leyendo BD');
  }
  return { investigations: [] };
}

function saveDB(data) {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
  } catch (e) {
    console.log('Error guardando BD');
  }
}

// DISCORD AUTH
app.get('/auth/discord', (req, res) => {
  const url = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}&response_type=code&scope=identify%20guilds.members.read`;
  res.redirect(url);
});

app.get('/auth/discord/callback', async (req, res) => {
  const code = req.query.code;
  
  try {
    // Obtener token
    const tokenRes = await axios.post('https://discord.com/api/oauth2/token', {
      client_id: DISCORD_CLIENT_ID,
      client_secret: DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: DISCORD_REDIRECT_URI
    });

    const accessToken = tokenRes.data.access_token;

    // Obtener usuario
    const userRes = await axios.get('https://discord.com/api/users/@me', {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    const user = userRes.data;

    // Obtener roles del servidor
    let roles = [];
    try {
      const memberRes = await axios.get(`https://discord.com/api/users/@me/guilds/${YOUR_GUILD_ID}/member`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });
      roles = memberRes.data.roles || [];
    } catch (e) {
      console.log('Error obteniendo roles');
    }

    // Verificar permiso
    if (!roles.includes(ALLOWED_ROLE)) {
      return res.redirect(`${process.env.FRONTEND_URL}?error=no-permission`);
    }

    // Crear token JWT
    const jwtToken = jwt.encode({
      id: user.id,
      username: user.username,
      avatar: `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`,
      roles
    }, JWT_SECRET);

    res.redirect(`${process.env.FRONTEND_URL}?token=${jwtToken}`);
  } catch (e) {
    console.error(e);
    res.redirect(`${process.env.FRONTEND_URL}?error=auth-failed`);
  }
});

// MIDDLEWARE AUTH
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    req.user = jwt.decode(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// API ENDPOINTS
app.get('/api/user', authMiddleware, (req, res) => {
  res.json(req.user);
});

app.get('/api/investigations', authMiddleware, (req, res) => {
  const db = loadDB();
  res.json(db.investigations);
});

app.post('/api/investigations', authMiddleware, (req, res) => {
  if (!req.user.roles.includes(EDIT_ROLE)) {
    return res.status(403).json({ error: 'No permission' });
  }

  const db = loadDB();
  const investigation = {
    id: Date.now().toString(),
    ...req.body,
    fecha: new Date().toLocaleString('es-CO'),
    createdBy: req.user.id,
    createdByUser: req.user.username,
    createdAt: new Date().toISOString()
  };

  db.investigations.push(investigation);
  saveDB(db);

  res.json(investigation);
});

app.put('/api/investigations/:id', authMiddleware, (req, res) => {
  if (!req.user.roles.includes(EDIT_ROLE)) {
    return res.status(403).json({ error: 'No permission' });
  }

  const db = loadDB();
  const idx = db.investigations.findIndex(i => i.id === req.params.id);

  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  if (db.investigations[idx].createdBy !== req.user.id) {
    return res.status(403).json({ error: 'Not author' });
  }

  db.investigations[idx] = { ...db.investigations[idx], ...req.body, lastModified: new Date().toISOString() };
  saveDB(db);

  res.json(db.investigations[idx]);
});

app.delete('/api/investigations/:id', authMiddleware, (req, res) => {
  if (!req.user.roles.includes(EDIT_ROLE)) {
    return res.status(403).json({ error: 'No permission' });
  }

  const db = loadDB();
  const idx = db.investigations.findIndex(i => i.id === req.params.id);

  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  if (db.investigations[idx].createdBy !== req.user.id) {
    return res.status(403).json({ error: 'Not author' });
  }

  db.investigations.splice(idx, 1);
  saveDB(db);

  res.json({ success: true });
});

app.post('/api/investigations/:id/copy', authMiddleware, (req, res) => {
  if (!req.user.roles.includes(EDIT_ROLE)) {
    return res.status(403).json({ error: 'No permission' });
  }

  const db = loadDB();
  const original = db.investigations.find(i => i.id === req.params.id);

  if (!original) return res.status(404).json({ error: 'Not found' });
  if (original.createdBy !== req.user.id) {
    return res.status(403).json({ error: 'Not author' });
  }

  const copy = {
    ...original,
    id: Date.now().toString(),
    titulo: `${original.titulo} (Copia)`,
    createdAt: new Date().toISOString()
  };

  db.investigations.push(copy);
  saveDB(db);

  res.json(copy);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend DEA en puerto ${PORT}`);
});
