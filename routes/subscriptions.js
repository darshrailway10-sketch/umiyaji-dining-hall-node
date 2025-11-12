const express = require('express');
const { body, query, validationResult } = require('express-validator');
const Subscription = require('../models/Subscription');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Validation rules
const subscriptionValidation = [
  body('studentName')
    .trim()
    .notEmpty()
    .withMessage('Student name is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Student name must be between 2 and 100 characters'),
  body('phone')
    .notEmpty()
    .withMessage('Phone number is required')
    .matches(/^\d{10}$/)
    .withMessage('Please enter a valid 10-digit phone number'),
  body('plan')
    .isIn(['weekly', 'monthly'])
    .withMessage('Plan must be either weekly or monthly'),
  body('startDate')
    .isISO8601()
    .withMessage('Invalid start date format')
    .custom((value) => {
      if (new Date(value) <= new Date()) {
        throw new Error('Start date must be in the future');
      }
      return true;
    }),
  body('endDate')
    .isISO8601()
    .withMessage('Invalid end date format'),
  body('price')
    .isFloat({ min: 0 })
    .withMessage('Price must be a positive number'),
  body('mealsIncluded')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Meals included must be a positive integer'),
  body('status')
    .optional()
    .isIn(['active', 'paused', 'expired', 'cancelled'])
    .withMessage('Invalid status')
].concat([
  // Custom validation for date range
  body('endDate').custom((value, { req }) => {
    if (new Date(value) <= new Date(req.body.startDate)) {
      throw new Error('End date must be after start date');
    }
    return true;
  })
]);

const updateSubscriptionValidation = [
  body('plan')
    .optional()
    .isIn(['weekly', 'monthly'])
    .withMessage('Plan must be either weekly or monthly'),
  body('startDate')
    .optional()
    .isISO8601()
    .withMessage('Invalid start date format'),
  body('endDate')
    .optional()
    .isISO8601()
    .withMessage('Invalid end date format'),
  body('price')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Price must be a positive number'),
  body('mealsIncluded')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Meals included must be a positive integer'),
  body('status')
    .optional()
    .isIn(['active', 'paused', 'expired', 'cancelled'])
    .withMessage('Invalid status')
];

// Create new subscription
router.post('/', subscriptionValidation, authenticateToken, async (req, res) => {
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

    const { studentName, phone, plan, startDate, endDate, price, mealsIncluded, status } = req.body;

    // Calculate meals included if not provided
    let calculatedMeals = mealsIncluded;
    if (!calculatedMeals) {
      calculatedMeals = plan === 'weekly' ? 7 : 30;
    }

    const subscription = new Subscription({
      studentName,
      phone,
      plan,
      startDate,
      endDate,
      price,
      mealsIncluded: calculatedMeals,
      status: status || 'active',
      createdBy: req.user._id
    });

    await subscription.save();

    res.status(201).json({
      success: true,
      message: 'Subscription created successfully',
      data: { subscription }
    });
  } catch (error) {
    console.error('Create subscription error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create subscription',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get all subscriptions with pagination and filters
router.get('/', authenticateToken, [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('status').optional().isIn(['active', 'paused', 'expired', 'cancelled']),
  query('plan').optional().isIn(['weekly', 'monthly']),
  query('phone').optional().isMobilePhone('any'),
  query('dateFrom').optional().isISO8601().withMessage('Invalid date format'),
  query('dateTo').optional().isISO8601().withMessage('Invalid date format')
], async (req, res) => {
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

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Build filter query
    const filter = {};
    
    if (req.query.status) {
      filter.status = req.query.status;
    }
    
    if (req.query.plan) {
      filter.plan = req.query.plan;
    }
    
    if (req.query.phone) {
      filter.phone = req.query.phone;
    }
    
    if (req.query.dateFrom || req.query.dateTo) {
      filter.startDate = {};
      if (req.query.dateFrom) {
        filter.startDate.$gte = new Date(req.query.dateFrom);
      }
      if (req.query.dateTo) {
        filter.startDate.$lte = new Date(req.query.dateTo);
      }
    }

    const subscriptions = await Subscription.find(filter)
      .populate('createdBy', 'name email')
      .sort({ startDate: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Subscription.countDocuments(filter);

    res.json({
      success: true,
      data: {
        subscriptions,
        pagination: {
          current: page,
          pages: Math.ceil(total / limit),
          total,
          limit
        }
      }
    });
  } catch (error) {
    console.error('Get subscriptions error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch subscriptions',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get subscription by ID
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const subscription = await Subscription.findById(req.params.id).populate('createdBy', 'name email');
    
    if (!subscription) {
      return res.status(404).json({
        success: false,
        message: 'Subscription not found'
      });
    }

    res.json({
      success: true,
      data: { subscription }
    });
  } catch (error) {
    console.error('Get subscription error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch subscription',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Update subscription
router.put('/:id', authenticateToken, updateSubscriptionValidation, async (req, res) => {
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

    const subscription = await Subscription.findByIdAndUpdate(
      req.params.id,
      { $set: req.body },
      { new: true, runValidators: true }
    ).populate('createdBy', 'name email');

    if (!subscription) {
      return res.status(404).json({
        success: false,
        message: 'Subscription not found'
      });
    }

    res.json({
      success: true,
      message: 'Subscription updated successfully',
      data: { subscription }
    });
  } catch (error) {
    console.error('Update subscription error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update subscription',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Update subscription status
router.patch('/:id/status', authenticateToken, [
  body('status')
    .isIn(['active', 'paused', 'expired', 'cancelled'])
    .withMessage('Invalid status')
], async (req, res) => {
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

    const subscription = await Subscription.findByIdAndUpdate(
      req.params.id,
      { $set: { status: req.body.status } },
      { new: true }
    ).populate('createdBy', 'name email');

    if (!subscription) {
      return res.status(404).json({
        success: false,
        message: 'Subscription not found'
      });
    }

    res.json({
      success: true,
      message: 'Subscription status updated successfully',
      data: { subscription }
    });
  } catch (error) {
    console.error('Update subscription status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update subscription status',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Delete subscription
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const subscription = await Subscription.findByIdAndDelete(req.params.id);
    
    if (!subscription) {
      return res.status(404).json({
        success: false,
        message: 'Subscription not found'
      });
    }

    res.json({
      success: true,
      message: 'Subscription deleted successfully'
    });
  } catch (error) {
    console.error('Delete subscription error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete subscription',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get subscription statistics
router.get('/stats/summary', authenticateToken, async (req, res) => {
  try {
    const { plan, status } = req.query;
    const matchStage = {};
    
    if (plan) matchStage.plan = plan;
    if (status) matchStage.status = status;
    
    const stats = await Subscription.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: null,
          totalSubscriptions: { $sum: 1 },
          totalRevenue: { $sum: '$price' },
          averagePrice: { $avg: '$price' },
          totalMealsIncluded: { $sum: '$mealsIncluded' }
        }
      }
    ]);

    const planBreakdown = await Subscription.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: '$plan',
          count: { $sum: 1 },
          revenue: { $sum: '$price' }
        }
      }
    ]);

    const statusBreakdown = await Subscription.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    const result = stats[0] || { 
      totalSubscriptions: 0, 
      totalRevenue: 0, 
      averagePrice: 0, 
      totalMealsIncluded: 0 
    };
    
    result.planBreakdown = planBreakdown;
    result.statusBreakdown = statusBreakdown;

    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    console.error('Subscription stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch subscription statistics',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get expiring subscriptions
router.get('/alerts/expiring', authenticateToken, async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + days);

    const expiringSubscriptions = await Subscription.find({
      status: 'active',
      endDate: {
        $gte: new Date(),
        $lte: futureDate
      }
    }).populate('createdBy', 'name email')
    .sort({ endDate: 1 });

    res.json({
      success: true,
      data: {
        subscriptions: expiringSubscriptions,
        count: expiringSubscriptions.length
      }
    });
  } catch (error) {
    console.error('Expiring subscriptions error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch expiring subscriptions',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Auto-expire subscriptions
router.post('/auto-expire', authenticateToken, async (req, res) => {
  try {
    const expiredSubscriptions = await Subscription.updateMany(
      {
        status: { $in: ['active', 'paused'] },
        endDate: { $lt: new Date() }
      },
      { $set: { status: 'expired' } }
    );

    res.json({
      success: true,
      message: `Auto-expired ${expiredSubscriptions.modifiedCount} subscriptions`,
      data: {
        modifiedCount: expiredSubscriptions.modifiedCount
      }
    });
  } catch (error) {
    console.error('Auto-expire subscriptions error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to auto-expire subscriptions',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;