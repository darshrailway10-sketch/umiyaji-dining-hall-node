const express = require('express');
const { body, query, validationResult } = require('express-validator');
const Attendance = require('../models/Attendance');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Validation rules
const attendanceValidation = [
  body('studentName')
    .trim()
    .notEmpty()
    .withMessage('Student name is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Student name must be between 2 and 100 characters'),
  body('studentPhone')
    .notEmpty()
    .withMessage('Student phone is required')
    .matches(/^\d{10}$/)
    .withMessage('Please enter a valid 10-digit phone number'),
  body('mealType')
    .isIn(['breakfast', 'lunch', 'dinner'])
    .withMessage('Meal type must be breakfast, lunch, or dinner'),
  body('date')
    .isISO8601()
    .withMessage('Invalid date format')
    .custom((value) => {
      const inputDate = new Date(value);
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      
      if (inputDate > today) {
        throw new Error('Attendance date cannot be in the future');
      }
      return true;
    }),
  body('price')
    .isFloat({ min: 0 })
    .withMessage('Price must be a positive number')
];

const bulkAttendanceValidation = [
  body('attendances')
    .isArray({ min: 1 })
    .withMessage('At least one attendance record is required'),
  body('attendances.*.studentName')
    .trim()
    .notEmpty()
    .withMessage('Student name is required'),
  body('attendances.*.studentPhone')
    .matches(/^\d{10}$/)
    .withMessage('Please enter a valid 10-digit phone number'),
  body('attendances.*.mealType')
    .isIn(['breakfast', 'lunch', 'dinner'])
    .withMessage('Meal type must be breakfast, lunch, or dinner'),
  body('attendances.*.date')
    .isISO8601()
    .withMessage('Invalid date format'),
  body('attendances.*.price')
    .isFloat({ min: 0 })
    .withMessage('Price must be a positive number')
];

// Create new attendance record
router.post('/', attendanceValidation, authenticateToken, async (req, res) => {
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

    const { studentName, studentPhone, mealType, date, price } = req.body;

    // Check for duplicate attendance record
    const existingAttendance = await Attendance.findOne({
      studentPhone,
      mealType,
      date: {
        $gte: new Date(date).setHours(0, 0, 0, 0),
        $lt: new Date(date).setHours(23, 59, 59, 999)
      }
    });

    if (existingAttendance) {
      return res.status(400).json({
        success: false,
        message: 'Attendance already recorded for this student, meal type, and date'
      });
    }

    const attendance = new Attendance({
      studentName,
      studentPhone,
      mealType,
      date,
      price,
      recordedBy: req.user._id
    });

    await attendance.save();

    res.status(201).json({
      success: true,
      message: 'Attendance recorded successfully',
      data: { attendance }
    });
  } catch (error) {
    console.error('Create attendance error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to record attendance',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Create multiple attendance records (bulk)
router.post('/bulk', bulkAttendanceValidation, authenticateToken, async (req, res) => {
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

    const { attendances } = req.body;

    // Check for duplicates before inserting
    const duplicates = [];
    for (const attendance of attendances) {
      const existing = await Attendance.findOne({
        studentPhone: attendance.studentPhone,
        mealType: attendance.mealType,
        date: {
          $gte: new Date(attendance.date).setHours(0, 0, 0, 0),
          $lt: new Date(attendance.date).setHours(23, 59, 59, 999)
        }
      });
      
      if (existing) {
        duplicates.push(`${attendance.studentName} - ${attendance.mealType} - ${attendance.date}`);
      }
    }

    if (duplicates.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Duplicate attendance records found',
        duplicates
      });
    }

    // Add recordedBy to all attendance records
    const attendanceRecords = attendances.map(attendance => ({
      ...attendance,
      recordedBy: req.user._id
    }));

    const createdAttendances = await Attendance.insertMany(attendanceRecords);

    res.status(201).json({
      success: true,
      message: `${createdAttendances.length} attendance records created successfully`,
      data: { 
        count: createdAttendances.length,
        attendances: createdAttendances 
      }
    });
  } catch (error) {
    console.error('Bulk create attendance error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create bulk attendance records',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get all attendance records with pagination and filters
router.get('/', authenticateToken, [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('mealType').optional().isIn(['breakfast', 'lunch', 'dinner']),
  query('studentPhone').optional().isMobilePhone('any'),
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
    
    if (req.query.mealType) {
      filter.mealType = req.query.mealType;
    }
    
    if (req.query.studentPhone) {
      filter.studentPhone = req.query.studentPhone;
    }
    
    if (req.query.dateFrom || req.query.dateTo) {
      filter.date = {};
      if (req.query.dateFrom) {
        filter.date.$gte = new Date(req.query.dateFrom);
      }
      if (req.query.dateTo) {
        filter.date.$lte = new Date(req.query.dateTo);
      }
    }

    const attendances = await Attendance.find(filter)
      .populate('recordedBy', 'name email')
      .sort({ date: -1, mealType: 1 })
      .skip(skip)
      .limit(limit);

    const total = await Attendance.countDocuments(filter);

    res.json({
      success: true,
      data: {
        attendances,
        pagination: {
          current: page,
          pages: Math.ceil(total / limit),
          total,
          limit
        }
      }
    });
  } catch (error) {
    console.error('Get attendance error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch attendance records',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get attendance by ID
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const attendance = await Attendance.findById(req.params.id).populate('recordedBy', 'name email');
    
    if (!attendance) {
      return res.status(404).json({
        success: false,
        message: 'Attendance record not found'
      });
    }

    res.json({
      success: true,
      data: { attendance }
    });
  } catch (error) {
    console.error('Get attendance error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch attendance record',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Update attendance record
router.put('/:id', authenticateToken, attendanceValidation, async (req, res) => {
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

    const attendance = await Attendance.findByIdAndUpdate(
      req.params.id,
      { $set: req.body },
      { new: true, runValidators: true }
    ).populate('recordedBy', 'name email');

    if (!attendance) {
      return res.status(404).json({
        success: false,
        message: 'Attendance record not found'
      });
    }

    res.json({
      success: true,
      message: 'Attendance record updated successfully',
      data: { attendance }
    });
  } catch (error) {
    console.error('Update attendance error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update attendance record',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Delete attendance record
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const attendance = await Attendance.findByIdAndDelete(req.params.id);
    
    if (!attendance) {
      return res.status(404).json({
        success: false,
        message: 'Attendance record not found'
      });
    }

    res.json({
      success: true,
      message: 'Attendance record deleted successfully'
    });
  } catch (error) {
    console.error('Delete attendance error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete attendance record',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get daily attendance summary
router.get('/stats/daily', authenticateToken, async (req, res) => {
  try {
    const { date, mealType } = req.query;
    
    if (!date) {
      return res.status(400).json({
        success: false,
        message: 'Date parameter is required'
      });
    }

    const startDate = new Date(date);
    startDate.setHours(0, 0, 0, 0);
    const endDate = new Date(date);
    endDate.setHours(23, 59, 59, 999);

    const matchStage = {
      date: { $gte: startDate, $lte: endDate }
    };
    
    if (mealType) {
      matchStage.mealType = mealType;
    }

    const summary = await Attendance.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: '$mealType',
          count: { $sum: 1 },
          totalRevenue: { $sum: '$price' },
          averagePrice: { $avg: '$price' }
        }
      }
    ]);

    const totalCount = summary.reduce((sum, item) => sum + item.count, 0);
    const totalRevenue = summary.reduce((sum, item) => sum + item.totalRevenue, 0);

    res.json({
      success: true,
      data: {
        date,
        mealType: mealType || 'all',
        totalCount,
        totalRevenue,
        averagePrice: totalCount > 0 ? totalRevenue / totalCount : 0,
        breakdown: summary
      }
    });
  } catch (error) {
    console.error('Daily attendance stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch daily attendance summary',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get attendance statistics
router.get('/stats/summary', authenticateToken, async (req, res) => {
  try {
    const { dateFrom, dateTo, mealType } = req.query;
    
    const matchStage = {};
    
    if (mealType) {
      matchStage.mealType = mealType;
    }
    
    if (dateFrom || dateTo) {
      matchStage.date = {};
      if (dateFrom) {
        matchStage.date.$gte = new Date(dateFrom);
      }
      if (dateTo) {
        matchStage.date.$lte = new Date(dateTo);
      }
    }

    const stats = await Attendance.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: null,
          totalRecords: { $sum: 1 },
          totalRevenue: { $sum: '$price' },
          averagePrice: { $avg: '$price' }
        }
      }
    ]);

    const mealTypeBreakdown = await Attendance.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: '$mealType',
          count: { $sum: 1 },
          revenue: { $sum: '$price' }
        }
      }
    ]);

    const topStudents = await Attendance.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: { studentName: '$studentName', studentPhone: '$studentPhone' },
          attendanceCount: { $sum: 1 },
          totalSpent: { $sum: '$price' }
        }
      },
      { $sort: { attendanceCount: -1 } },
      { $limit: 10 }
    ]);

    const result = stats[0] || { totalRecords: 0, totalRevenue: 0, averagePrice: 0 };
    result.mealTypeBreakdown = mealTypeBreakdown;
    result.topStudents = topStudents;

    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    console.error('Attendance stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch attendance statistics',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get student attendance history
router.get('/student/:phone/history', authenticateToken, async (req, res) => {
  try {
    const { phone } = req.params;
    const { page = 1, limit = 20, dateFrom, dateTo } = req.query;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const filter = { studentPhone: phone };
    
    if (dateFrom || dateTo) {
      filter.date = {};
      if (dateFrom) {
        filter.date.$gte = new Date(dateFrom);
      }
      if (dateTo) {
        filter.date.$lte = new Date(dateTo);
      }
    }

    const attendances = await Attendance.find(filter)
      .populate('recordedBy', 'name email')
      .sort({ date: -1, mealType: 1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Attendance.countDocuments(filter);

    // Calculate summary for this student
    const summary = await Attendance.aggregate([
      { $match: { studentPhone: phone } },
      {
        $group: {
          _id: null,
          totalVisits: { $sum: 1 },
          totalSpent: { $sum: '$price' },
          breakfastCount: {
            $sum: { $cond: [{ $eq: ['$mealType', 'breakfast'] }, 1, 0] }
          },
          lunchCount: {
            $sum: { $cond: [{ $eq: ['$mealType', 'lunch'] }, 1, 0] }
          },
          dinnerCount: {
            $sum: { $cond: [{ $eq: ['$mealType', 'dinner'] }, 1, 0] }
          }
        }
      }
    ]);

    res.json({
      success: true,
      data: {
        attendances,
        pagination: {
          current: parseInt(page),
          pages: Math.ceil(total / parseInt(limit)),
          total,
          limit: parseInt(limit)
        },
        summary: summary[0] || {
          totalVisits: 0,
          totalSpent: 0,
          breakfastCount: 0,
          lunchCount: 0,
          dinnerCount: 0
        }
      }
    });
  } catch (error) {
    console.error('Student attendance history error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch student attendance history',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;