const express = require('express');
const Order = require('../models/Order');
const Meal = require('../models/Meal');
const Attendance = require('../models/Attendance');
const Subscription = require('../models/Subscription');
const Bill = require('../models/Bill');

const router = express.Router();

// GET /api/analytics - Get all analytics data
router.get('/', async (req, res) => {
  try {
    // Get current date and date ranges
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);
    const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
    const monthAgo = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);

    // Total counts
    const totalOrders = await Order.countDocuments();
    const totalMeals = await Meal.countDocuments();
    const totalAttendance = await Attendance.countDocuments();
    const totalSubscriptions = await Subscription.countDocuments();
    const totalBills = await Bill.countDocuments();

    // Today's data
    const todayOrders = await Order.countDocuments({
      orderDate: { $gte: today }
    });

    const todayAttendance = await Attendance.countDocuments({
      date: { $gte: today }
    });

    // Orders by status
    const ordersByStatus = await Order.aggregate([
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    // Meals by type
    const mealsByType = await Meal.aggregate([
      {
        $group: {
          _id: '$type',
          count: { $sum: 1 },
          avgPrice: { $avg: '$price' }
        }
      }
    ]);

    // Revenue data (last 30 days)
    const revenueData = await Attendance.aggregate([
      {
        $match: {
          date: { $gte: monthAgo }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$date' },
            month: { $month: '$date' },
            day: { $dayOfMonth: '$date' }
          },
          revenue: { $sum: '$price' },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 }
      }
    ]);

    // Top meals by orders
    const topMeals = await Order.aggregate([
      { $unwind: '$items' },
      {
        $group: {
          _id: '$items.mealName',
          count: { $sum: '$items.quantity' },
          revenue: { $sum: { $multiply: ['$items.quantity', '$items.price'] } }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    // Attendance trends (last 7 days)
    const attendanceTrends = await Attendance.aggregate([
      {
        $match: {
          date: { $gte: weekAgo }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$date' },
            month: { $month: '$date' },
            day: { $dayOfMonth: '$date' },
            mealType: '$mealType'
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 }
      }
    ]);

    // Active subscriptions
    const activeSubscriptions = await Subscription.countDocuments({
      status: 'active',
      endDate: { $gte: now }
    });

    // Bills by status
    const billsByStatus = await Bill.aggregate([
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 },
          totalAmount: { $sum: '$totalAmount' }
        }
      }
    ]);

    res.json({
      success: true,
      data: {
        overview: {
          totalOrders,
          totalMeals,
          totalAttendance,
          totalSubscriptions,
          totalBills,
          todayOrders,
          todayAttendance,
          activeSubscriptions
        },
        ordersByStatus,
        mealsByType,
        revenueData,
        topMeals,
        attendanceTrends,
        billsByStatus
      }
    });
  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch analytics data'
    });
  }
});

module.exports = router;