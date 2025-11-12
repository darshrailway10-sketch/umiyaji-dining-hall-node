const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const Notification = require('../models/Notification');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Validation rules
const notificationValidation = [
  body('studentPhone')
    .matches(/^\d{10}$/)
    .withMessage('Please enter a valid 10-digit phone number'),
  body('studentName')
    .trim()
    .notEmpty()
    .withMessage('Student name is required'),
  body('title')
    .trim()
    .notEmpty()
    .withMessage('Title is required')
    .isLength({ max: 100 })
    .withMessage('Title cannot exceed 100 characters'),
  body('message')
    .trim()
    .notEmpty()
    .withMessage('Message is required')
    .isLength({ max: 500 })
    .withMessage('Message cannot exceed 500 characters'),
  body('type')
    .optional()
    .isIn(['order', 'attendance', 'bill', 'subscription', 'menu', 'general'])
    .withMessage('Invalid notification type')
];

// GET /api/notifications/user/:phone - Get notifications for user
router.get('/user/:phone', [
  param('phone').matches(/^\d{10}$/).withMessage('Invalid phone number')
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

    const { limit = 50 } = req.query;
    const limitNum = Math.min(parseInt(limit), 100); // Max 100 notifications

    const notifications = await Notification.find({ studentPhone: req.params.phone })
      .populate('sentBy', 'name')
      .sort({ createdAt: -1 })
      .limit(limitNum);

    res.json({
      success: true,
      data: notifications
    });
  } catch (error) {
    console.error('Get user notifications error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch notifications'
    });
  }
});

// GET /api/notifications/count/:phone - Get unread notification count
router.get('/count/:phone', [
  param('phone').matches(/^\d{10}$/).withMessage('Invalid phone number')
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

    const count = await Notification.countDocuments({
      studentPhone: req.params.phone,
      read: false
    });

    res.json({
      success: true,
      data: { unreadCount: count }
    });
  } catch (error) {
    console.error('Get notification count error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch notification count'
    });
  }
});

// PATCH /api/notifications/:id/read - Mark notification as read
router.patch('/:id/read', authenticateToken, [
  param('id').isMongoId().withMessage('Invalid notification ID')
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

    const notification = await Notification.findByIdAndUpdate(
      req.params.id,
      { read: true },
      { new: true }
    );

    if (!notification) {
      return res.status(404).json({
        success: false,
        message: 'Notification not found'
      });
    }

    res.json({
      success: true,
      message: 'Notification marked as read',
      data: notification
    });
  } catch (error) {
    console.error('Mark notification read error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to mark notification as read'
    });
  }
});

// POST /api/notifications - Send single notification
router.post('/', authenticateToken, notificationValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const notification = new Notification({
      ...req.body,
      sentBy: req.user._id
    });
    await notification.save();

    // Send real-time notification
    if (global.sendNotificationToUser) {
      global.sendNotificationToUser(notification.studentPhone, notification);
    }

    res.status(201).json({
      success: true,
      message: 'Notification sent successfully',
      data: notification
    });
  } catch (error) {
    console.error('Send notification error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send notification'
    });
  }
});

// POST /api/notifications/batch - Send batch notifications
router.post('/batch', authenticateToken, [
  body('notifications').isArray({ min: 1 }).withMessage('Notifications array is required'),
  body('notifications.*.studentPhone').matches(/^\d{10}$/).withMessage('Invalid phone number'),
  body('notifications.*.studentName').notEmpty().withMessage('Student name required'),
  body('notifications.*.title').notEmpty().withMessage('Title required'),
  body('notifications.*.message').notEmpty().withMessage('Message required')
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

    const { notifications } = req.body;

    // Validate each notification
    for (const notif of notifications) {
      const validationErrors = validationResult(notif);
      if (!validationErrors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Invalid notification in batch',
          errors: validationErrors.array()
        });
      }
    }

    // Create notifications with sentBy field
    const notificationsWithSender = notifications.map(notif => ({
      ...notif,
      sentBy: req.user._id
    }));

    const savedNotifications = await Notification.insertMany(notificationsWithSender);

    // Send real-time notifications
    if (global.sendNotificationToUser) {
      savedNotifications.forEach(notification => {
        global.sendNotificationToUser(notification.studentPhone, notification);
      });
    }

    res.status(201).json({
      success: true,
      message: `Successfully sent ${savedNotifications.length} notifications`,
      data: savedNotifications
    });
  } catch (error) {
    console.error('Send batch notifications error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send batch notifications'
    });
  }
});

module.exports = router;