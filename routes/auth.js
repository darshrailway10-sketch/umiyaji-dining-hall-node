const express = require('express');
const jwt = require('jsonwebtoken');
const { body, param, validationResult } = require('express-validator');
const User = require('../models/User');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Validation rules
const registerValidation = [
  body('name')
    .trim()
    .notEmpty()
    .withMessage('Name is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be between 2 and 100 characters'),
  body('email')
    .optional()
    .isEmail()
    .withMessage('Please enter a valid email')
    .normalizeEmail(),
  body('phone')
    .notEmpty()
    .withMessage('Phone number is required')
    .matches(/^\d{10}$/)
    .withMessage('Please enter a valid 10-digit phone number'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long'),
  body('role')
    .optional()
    .isIn(['user', 'owner'])
    .withMessage('Role must be either user or owner'),
  body('ownerPhone')
    .optional()
    .matches(/^\d{10}$/)
    .withMessage('Please enter a valid 10-digit owner phone number')
];

const loginValidation = [
  body('phone')
    .notEmpty()
    .withMessage('Phone number is required')
    .matches(/^\d{10}$/)
    .withMessage('Please enter a valid 10-digit phone number'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

// Helper function to generate JWT token
const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d'
  });
};

// Register new user
router.post('/register', registerValidation, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { name, email, phone, password, role = 'user', ownerPhone } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ phone }, { email: email || '' }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: existingUser.phone === phone 
          ? 'Phone number already registered' 
          : 'Email already registered'
      });
    }

    // For regular users, check if owner exists
    if (role === 'user' && ownerPhone) {
      const owner = await User.findOne({ phone: ownerPhone, role: 'owner' });
      if (!owner) {
        return res.status(400).json({
          success: false,
          message: 'Owner phone number not found'
        });
      }
    }

    // Determine approval status
    // Owners are auto-approved, users need approval
    const approvalStatus = role === 'owner' ? 'approved' : 'pending';

    // Create new user
    const user = new User({
      name,
      email: email || undefined, // Only include if provided
      phone,
      password,
      role,
      ownerPhone: role === 'user' && ownerPhone ? ownerPhone : undefined,
      approvalStatus
    });

    await user.save();

    // Send WebSocket notification to owner if user signup is pending
    if (approvalStatus === 'pending' && role === 'user' && ownerPhone) {
      try {
        const websocketService = require('../service/socket/websocket');
        websocketService.sendToRole('owner', 'user_signup', {
          user: {
            _id: user._id,
            name: user.name,
            phone: user.phone,
            email: user.email,
            role: user.role,
            approvalStatus: user.approvalStatus,
            createdAt: user.createdAt
          }
        });
      } catch (error) {
        console.error('Error sending WebSocket notification:', error);
      }
    }

    // Only generate token if approved (owners are auto-approved)
    let token = null;
    if (approvalStatus === 'approved') {
      token = generateToken(user._id);
    user.lastLogin = new Date();
    await user.save();
    }

    res.status(201).json({
      success: true,
      message: role === 'owner' 
        ? 'User registered successfully' 
        : 'Registration request sent. You will receive a notification when approved.',
      data: {
        user: {
          uid: user._id,
          email: user.email,
          phone: user.phone,
          name: user.name,
          role: user.role,
          approvalStatus: user.approvalStatus,
          createdAt: user.createdAt
        },
        token // null for pending users
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Registration failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Login user
router.post('/login', loginValidation, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { phone, password } = req.body;

    // Find user by phone
    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid phone number or password'
      });
    }

    // Check if user is active
    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Account is deactivated'
      });
    }

    // Check approval status - declined users cannot login
    if (user.approvalStatus === 'declined') {
      return res.status(403).json({
        success: false,
        message: 'Your registration request has been declined. Please contact the owner.'
      });
    }

    // Check if user is pending approval
    if (user.approvalStatus === 'pending') {
      return res.status(403).json({
        success: false,
        message: 'Your registration request is pending approval. You will receive a notification when approved.'
      });
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid phone number or password'
      });
    }

    // Generate token
    const token = generateToken(user._id);

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          uid: user._id,
          email: user.email,
          phone: user.phone,
          name: user.name,
          role: user.role,
          createdAt: user.createdAt
        },
        token
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get current user profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        user: {
          uid: req.user._id,
          email: req.user.email,
          phone: req.user.phone,
          name: req.user.name,
          role: req.user.role,
          createdAt: req.user.createdAt,
          lastLogin: req.user.lastLogin
        }
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch profile',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Verify token endpoint
router.get('/verify', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'Token is valid',
    data: {
      user: {
        uid: req.user._id,
        email: req.user.email,
        phone: req.user.phone,
        name: req.user.name,
        role: req.user.role
      }
    }
  });
});

// Logout (optional - mainly for client-side token removal)
router.post('/logout', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'Logout successful'
  });
});

// GET /api/auth/pending - Get all pending users (owner only)
router.get('/pending', authenticateToken, async (req, res) => {
  try {
    // Check if user is owner
    if (req.user.role !== 'owner') {
      return res.status(403).json({
        success: false,
        message: 'Only owners can view pending users'
      });
    }

    // Get all pending users
    const pendingUsers = await User.find({ 
      approvalStatus: 'pending',
      role: 'user'
    }).select('-password').sort({ createdAt: -1 });

    res.json({
      success: true,
      data: pendingUsers
    });
  } catch (error) {
    console.error('Get pending users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch pending users'
    });
  }
});

// PATCH /api/auth/:id/approve - Approve a pending user (owner only)
router.patch('/:id/approve', authenticateToken, [
  param('id').isMongoId().withMessage('Invalid user ID')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    // Check if user is owner
    if (req.user.role !== 'owner') {
      return res.status(403).json({
        success: false,
        message: 'Only owners can approve users'
      });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.approvalStatus !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'User is not pending approval'
      });
    }

    // Approve user
    user.approvalStatus = 'approved';
    await user.save();

    res.json({
      success: true,
      message: 'User approved successfully',
      data: {
        user: {
          uid: user._id,
          email: user.email,
          phone: user.phone,
          name: user.name,
          role: user.role,
          approvalStatus: user.approvalStatus
        }
      }
    });
  } catch (error) {
    console.error('Approve user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to approve user'
    });
  }
});

// PATCH /api/auth/:id/decline - Decline a pending user (owner only)
router.patch('/:id/decline', authenticateToken, [
  param('id').isMongoId().withMessage('Invalid user ID')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    // Check if user is owner
    if (req.user.role !== 'owner') {
      return res.status(403).json({
        success: false,
        message: 'Only owners can decline users'
      });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.approvalStatus !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'User is not pending approval'
      });
    }

    // Decline user
    user.approvalStatus = 'declined';
    await user.save();

    res.json({
      success: true,
      message: 'User declined successfully',
      data: {
        user: {
          uid: user._id,
          email: user.email,
          phone: user.phone,
          name: user.name,
          role: user.role,
          approvalStatus: user.approvalStatus
        }
      }
    });
  } catch (error) {
    console.error('Decline user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to decline user'
    });
  }
});

module.exports = router;