const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const Bill = require('../models/Bill');
const Attendance = require('../models/Attendance');
const Notification = require('../models/Notification');
const { authenticateToken, requireOwner } = require('../middleware/auth');

const router = express.Router();

// Validation rules
const billValidation = [
  body('studentName')
    .trim()
    .notEmpty()
    .withMessage('Student name is required'),
  body('studentPhone')
    .matches(/^\d{10}$/)
    .withMessage('Please enter a valid 10-digit phone number'),
  body('startDate')
    .isISO8601()
    .withMessage('Valid start date is required'),
  body('endDate')
    .isISO8601()
    .withMessage('Valid end date is required')
];

// GET /api/bills - Get all bills
router.get('/', async (req, res) => {
  try {
    const { studentPhone, status } = req.query;
    const query = {};

    if (studentPhone) query.studentPhone = studentPhone;
    if (status) query.status = status;

    const bills = await Bill.find(query).sort({ createdAt: -1 });
    
    res.json({
      success: true,
      data: bills
    });
  } catch (error) {
    console.error('Get bills error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch bills'
    });
  }
});

// GET /api/bills/:id - Get specific bill
router.get('/:id', [
  param('id').isMongoId().withMessage('Invalid bill ID')
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

    const bill = await Bill.findById(req.params.id);

    if (!bill) {
      return res.status(404).json({
        success: false,
        message: 'Bill not found'
      });
    }

    res.json({
      success: true,
      data: bill
    });
  } catch (error) {
    console.error('Get bill error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch bill'
    });
  }
});

// GET /api/bills/student/:phone - Get bills by student phone
router.get('/student/:phone', [
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

    const bills = await Bill.find({ studentPhone: req.params.phone })
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      data: bills
    });
  } catch (error) {
    console.error('Get student bills error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch student bills'
    });
  }
});

// POST /api/bills/generate - Generate bill from attendance records
router.post('/generate', authenticateToken, requireOwner, billValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { studentName, studentPhone, startDate, endDate } = req.body;

    // Get attendance records for the date range
    const attendanceRecords = await Attendance.find({
      studentPhone,
      date: {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      }
    }).sort({ date: 1 });

    if (attendanceRecords.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No attendance records found for the selected date range'
      });
    }

    // Generate bill number
    const billCount = await Bill.countDocuments();
    const billNumber = `BILL${String(billCount + 1).padStart(6, '0')}`;

    // Calculate totals
    const totalMeals = attendanceRecords.length;
    const totalAmount = attendanceRecords.reduce((sum, record) => sum + record.price, 0);

    // Create meals array for bill
    const meals = attendanceRecords.map(record => ({
      date: record.date,
      type: record.mealType,
      price: record.price
    }));

    const bill = new Bill({
      billNumber,
      studentName,
      studentPhone,
      startDate: new Date(startDate),
      endDate: new Date(endDate),
      totalMeals,
      totalAmount,
      meals,
      generatedBy: req.user._id
    });
    await bill.save();

    // Create notification
    const notification = new Notification({
      studentPhone,
      studentName,
      title: 'Bill Generated',
      message: `Your bill for ${startDate} to ${endDate} has been generated. Total: ₹${totalAmount}`,
      type: 'bill',
      relatedId: bill._id,
      relatedModel: 'Bill',
      sentBy: req.user._id
    });
    await notification.save();

    if (global.sendNotificationToUser) {
      global.sendNotificationToUser(studentPhone, notification);
    }

    res.status(201).json({
      success: true,
      message: 'Bill generated successfully',
      data: bill
    });
  } catch (error) {
    console.error('Generate bill error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate bill'
    });
  }
});

// GET /api/bills/attendance-history/:phone - Get attendance history for billing
router.get('/attendance-history/:phone', [
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

    const { startDate, endDate } = req.query;
    const query = { studentPhone: req.params.phone };

    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate);
      if (endDate) query.date.$lte = new Date(endDate);
    }

    const attendanceHistory = await Attendance.find(query).sort({ date: -1 });

    res.json({
      success: true,
      data: attendanceHistory
    });
  } catch (error) {
    console.error('Get attendance history error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch attendance history'
    });
  }
});

// PATCH /api/bills/:id/status - Update bill status
router.patch('/:id/status', authenticateToken, requireOwner, [
  param('id').isMongoId().withMessage('Invalid bill ID'),
  body('status').isIn(['generated', 'sent', 'paid', 'overdue'])
    .withMessage('Invalid status')
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

    const bill = await Bill.findByIdAndUpdate(
      req.params.id,
      { status: req.body.status },
      { new: true, runValidators: true }
    );

    if (!bill) {
      return res.status(404).json({
        success: false,
        message: 'Bill not found'
      });
    }

    res.json({
      success: true,
      message: 'Bill status updated successfully',
      data: bill
    });
  } catch (error) {
    console.error('Update bill status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update bill status'
    });
  }
});

module.exports = router;