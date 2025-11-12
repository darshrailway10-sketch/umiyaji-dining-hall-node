const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
const websocketService = require('./service/socket/websocket');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8000;

// Trust proxy for proper IP detection behind load balancers/proxies
app.set('trust proxy', 1);

// Security middleware
app.use(helmet());

// Enhanced CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:5173',  // Vite dev server
      'http://localhost:3000',  // Alternative dev port
      'https://umiyaji-dining-hall-f.onrender.com',  // Deployed frontend
      'https://localhost',       // HTTPS localhost
      'https://127.0.0.1'       // HTTPS localhost IP
    ];
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(null, true); // Temporarily allow all origins for debugging
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

app.use(cors(corsOptions));
app.use(morgan('combined'));

// Rate limiting
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 100, // limit each IP to 100 requests per windowMs
//   message: 'Too many requests from this IP, please try again later.'
// });
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/dining_hall', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
  console.log('✅ Connected to MongoDB database');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err);
});

// Import routes
const authRoutes = require('./routes/auth');
const mealsRoutes = require('./routes/meals');
const ordersRoutes = require('./routes/orders');
const subscriptionsRoutes = require('./routes/subscriptions');
const clientsRoutes = require('./routes/clients');
const attendanceRoutes = require('./routes/attendance');
const billsRoutes = require('./routes/bills');
const analyticsRoutes = require('./routes/analytics');
const notificationsRoutes = require('./routes/notifications');

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/meals', mealsRoutes);
app.use('/api/orders', ordersRoutes);
app.use('/api/subscriptions', subscriptionsRoutes);
app.use('/api/clients', clientsRoutes);
app.use('/api/attendance', attendanceRoutes);
app.use('/api/bills', billsRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/notifications', notificationsRoutes);

// WebSocket setup for real-time features
const server = app.listen(PORT, () => {
  console.log('🚀 Server running on port ' + PORT);
  console.log('📝 API Documentation: http://localhost:' + PORT + '/api/docs');
  console.log('🏥 Health Check: http://localhost:' + PORT + '/health');
});

// Initialize WebSocket service
websocketService.initialize(server);

// Make websocketService available globally for routes
global.websocketService = websocketService;

// Keep backward compatibility for sendNotificationToUser
global.sendNotificationToUser = (userId, notification) => {
  websocketService.sendToUser(userId, 'notification', notification);
};

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found',
    path: req.path
  });
});

// Serve React app for all non-API routes (SPA fallback)
// This handles direct page refreshes on routes like /admin/analytics
app.get('*', (req, res) => {
  // Only serve index.html for HTML requests (not for API calls, images, etc.)
  if (req.accepts('html') && !req.path.startsWith('/api/')) {
    res.sendFile(path.join(__dirname, '../front/dist/index.html'));
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Global error handler:', err);

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(val => val.message);
    return res.status(400).json({
      success: false,
      message: 'Validation Error',
      errors: errors
    });
  }

  // Mongoose duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return res.status(400).json({
      success: false,
      message: field + ' already exists'
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      message: 'Invalid token'
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      message: 'Token expired'
    });
  }

  // Default server error
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { error: err.message })
  });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Graceful shutdown initiated...');
  
  // Close WebSocket connections
  websocketService.closeAll();
  
  // Close MongoDB connection
  await mongoose.connection.close();
  
  console.log('✅ Server shutdown complete');
  process.exit(0);
});

module.exports = app;