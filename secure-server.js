const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');

// Security Configuration
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  throw new Error('JWT_SECRET environment variable is required');
})();

const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || (() => {
  throw new Error('ADMIN_PASSWORD_HASH environment variable is required');
})();

const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(',') || ['https://localhost:3000'];

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: { error: 'Too many login attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later' },
});

app.use(generalLimiter);
app.use(express.json({ limit: '10mb' }));

// CORS configuration
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// Input validation middleware
const validateInput = (schema) => {
  return (req, res, next) => {
    const { error } = schema.validate(req.body);
    if (error) {
      logger.warn('Input validation failed', { 
        ip: req.ip, 
        path: req.path, 
        error: error.details[0].message 
      });
      return res.status(400).json({ error: 'Invalid input data' });
    }
    next();
  };
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    logger.warn('Missing authentication token', { ip: req.ip, path: req.path });
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      logger.warn('Invalid authentication token', { ip: req.ip, path: req.path });
      return res.status(403).json({ error: 'Invalid access token' });
    }
    req.user = user;
    next();
  });
};

// Server data (in production, use encrypted database)
const servers = {
  github: {name: 'GitHub MCP Server', description: 'Repository management, issues, PRs', status: 'stopped'},
  brave: {name: 'Brave Search MCP Server', description: 'Web and local search', status: 'stopped'},
  puppeteer: {name: 'Puppeteer MCP Server', description: 'Browser automation', status: 'stopped'},
  playwright: {name: 'Playwright MCP Server', description: 'Advanced browser testing', status: 'stopped'},
  sequential: {name: 'Sequential Thinking MCP Server', description: 'Complex problem-solving workflows', status: 'stopped'}
};

const apiKeys = new Map();
const activeSessions = new Set();

// Request logging
app.use((req, res, next) => {
  logger.info('Request received', {
    method: req.method,
    path: req.path,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  next();
});

// Root endpoint (minimal info)
app.get('/', (req, res) => {
  res.json({
    message: 'MCP Server API',
    version: '1.0.0',
    status: 'online'
  });
});

// Secure login endpoint
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    
    if (!password || typeof password !== 'string') {
      logger.warn('Login attempt with invalid password format', { ip: req.ip });
      return res.status(400).json({ error: 'Password is required' });
    }

    const isValid = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    
    if (!isValid) {
      logger.warn('Failed login attempt', { ip: req.ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const sessionId = uuidv4();
    const token = jwt.sign(
      { admin: true, sessionId }, 
      JWT_SECRET, 
      { expiresIn: '2h' } // Reduced from 24h
    );
    
    activeSessions.add(sessionId);
    
    logger.info('Successful login', { ip: req.ip, sessionId });
    res.json({ success: true, token, user: 'admin' });
    
  } catch (error) {
    logger.error('Login error', { error: error.message, ip: req.ip });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout endpoint
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  const { sessionId } = req.user;
  activeSessions.delete(sessionId);
  logger.info('User logged out', { sessionId });
  res.json({ message: 'Logged out successfully' });
});

// Enhanced auth middleware that checks active sessions
const authenticateActiveSession = (req, res, next) => {
  authenticateToken(req, res, (err) => {
    if (err) return;
    
    if (!activeSessions.has(req.user.sessionId)) {
      logger.warn('Attempted use of revoked session', { 
        sessionId: req.user.sessionId, 
        ip: req.ip 
      });
      return res.status(401).json({ error: 'Session expired' });
    }
    next();
  });
};

// Server management endpoints
app.get('/api/servers', authenticateActiveSession, (req, res) => {
  const serverList = Object.entries(servers).map(([id, server]) => ({
    id: validator.escape(id),
    ...server
  }));
  res.json(serverList);
});

app.post('/api/servers/:id/install', authenticateActiveSession, (req, res) => {
  const id = validator.escape(req.params.id);
  
  if (!servers[id]) {
    logger.warn('Attempt to install non-existent server', { id, ip: req.ip });
    return res.status(404).json({ error: 'Server not found' });
  }
  
  logger.info('Server installation requested', { id, ip: req.ip });
  res.json({ message: `${servers[id].name} installed successfully` });
});

app.post('/api/servers/:id/start', authenticateActiveSession, (req, res) => {
  const id = validator.escape(req.params.id);
  
  if (!servers[id]) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  servers[id].status = 'running';
  logger.info('Server started', { id, ip: req.ip });
  res.json({ message: `${servers[id].name} started successfully` });
});

app.post('/api/servers/:id/stop', authenticateActiveSession, (req, res) => {
  const id = validator.escape(req.params.id);
  
  if (!servers[id]) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  servers[id].status = 'stopped';
  logger.info('Server stopped', { id, ip: req.ip });
  res.json({ message: `${servers[id].name} stopped successfully` });
});

app.post('/api/servers/:id/restart', authenticateActiveSession, (req, res) => {
  const id = validator.escape(req.params.id);
  
  if (!servers[id]) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  servers[id].status = 'running';
  logger.info('Server restarted', { id, ip: req.ip });
  res.json({ message: `${servers[id].name} restarted successfully` });
});

// Status endpoint
app.get('/api/status', authenticateActiveSession, (req, res) => {
  const running = Object.values(servers).filter(s => s.status === 'running').length;
  res.json({
    activeServers: running,
    totalServers: Object.keys(servers).length,
    timestamp: new Date().toISOString()
  });
});

// API Key management
app.get('/api/keys', authenticateActiveSession, (req, res) => {
  const keys = Array.from(apiKeys.values()).map(key => ({
    id: key.id,
    name: validator.escape(key.name),
    active: key.active,
    created: key.created
  }));
  res.json(keys);
});

app.post('/api/keys', authenticateActiveSession, (req, res) => {
  const { name } = req.body;
  
  if (!name || typeof name !== 'string' || name.length > 100) {
    return res.status(400).json({ error: 'Valid name is required (max 100 chars)' });
  }
  
  const keyId = uuidv4();
  const token = uuidv4();
  const key = {
    id: keyId,
    name: validator.escape(name),
    token,
    active: true,
    created: new Date().toISOString()
  };
  
  apiKeys.set(keyId, key);
  logger.info('API key created', { keyId, name: key.name, ip: req.ip });
  res.json({ id: keyId, token });
});

app.delete('/api/keys/:id', authenticateActiveSession, (req, res) => {
  const id = validator.escape(req.params.id);
  
  if (!apiKeys.has(id)) {
    return res.status(404).json({ error: 'API key not found' });
  }
  
  apiKeys.get(id).active = false;
  logger.info('API key revoked', { keyId: id, ip: req.ip });
  res.json({ message: 'API key revoked' });
});

// Tool execution endpoint
app.post('/api/servers/:id/tools/:tool', authenticateActiveSession, (req, res) => {
  const id = validator.escape(req.params.id);
  const tool = validator.escape(req.params.tool);
  const { args } = req.body;
  
  if (!servers[id]) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  // Validate args array
  if (args && (!Array.isArray(args) || args.length > 10)) {
    return res.status(400).json({ error: 'Invalid arguments' });
  }
  
  logger.info('Tool execution requested', { 
    serverId: id, 
    tool, 
    argsCount: args?.length || 0, 
    ip: req.ip 
  });
  
  res.json({
    result: `Executed ${id}:${tool} with ${args?.length || 0} arguments`
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { 
    error: err.message, 
    stack: err.stack, 
    ip: req.ip, 
    path: req.path 
  });
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  logger.warn('404 - Route not found', { path: req.path, ip: req.ip });
  res.status(404).json({ error: 'Route not found' });
});

// Clean up expired sessions every hour
setInterval(() => {
  const now = Date.now();
  activeSessions.forEach(sessionId => {
    // This is simplified - in production, store session timestamps
    logger.info('Session cleanup check', { sessionId });
  });
}, 60 * 60 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Secure MCP API Server running on port ${PORT}`);
});

module.exports = app;