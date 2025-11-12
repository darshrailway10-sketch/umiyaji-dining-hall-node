const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const Meal = require('../models/Meal');
const { authenticateToken, requireOwner } = require('../middleware/auth');

const router = express.Router();

// Validation rules
const mealValidation = [
  body('name')
    .trim()
    .notEmpty()
    .withMessage('Meal name is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Meal name must be between 2 and 100 characters'),
  body('type')
    .isIn(['breakfast', 'lunch', 'dinner'])
    .withMessage('Meal type must be breakfast, lunch, or dinner'),
  body('price')
    .isNumeric()
    .custom((value) => {
      if (value < 0) {
        throw new Error('Price cannot be negative');
      }
      return true;
    }),
  body('prepTime')
    .trim()
    .notEmpty()
    .withMessage('Preparation time is required')
    .isLength({ max: 50 })
    .withMessage('Preparation time cannot exceed 50 characters')
];

// GET /api/meals - Get all meals
router.get('/', async (req, res) => {
  try {
    const { type } = req.query;
    const query = type ? { type } : {};
    
    const meals = await Meal.find(query).sort({ createdAt: -1 });
    
    res.json({
      success: true,
      data: meals
    });
  } catch (error) {
    console.error('Get meals error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch meals'
    });
  }
});

// GET /api/meals/:id - Get specific meal
router.get('/:id', [
  param('id').isMongoId().withMessage('Invalid meal ID')
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

    const meal = await Meal.findById(req.params.id);
    
    if (!meal) {
      return res.status(404).json({
        success: false,
        message: 'Meal not found'
      });
    }

    res.json({
      success: true,
      data: meal
    });
  } catch (error) {
    console.error('Get meal error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch meal'
    });
  }
});

// POST /api/meals - Create new meal (owner only)
router.post('/', authenticateToken, requireOwner, mealValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const meal = new Meal(req.body);
    await meal.save();

    // Broadcast meal creation to all connected clients
    if (global.websocketService) {
      global.websocketService.broadcastMealUpdate('created', meal);
    }

    res.status(201).json({
      success: true,
      message: 'Meal created successfully',
      data: meal
    });
  } catch (error) {
    console.error('Create meal error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create meal'
    });
  }
});

// PUT /api/meals/:id - Update meal (owner only)
router.put('/:id', authenticateToken, requireOwner, [
  param('id').isMongoId().withMessage('Invalid meal ID'),
  ...mealValidation
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

    const meal = await Meal.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );

    if (!meal) {
      return res.status(404).json({
        success: false,
        message: 'Meal not found'
      });
    }

    // Broadcast meal update to all connected clients
    if (global.websocketService) {
      global.websocketService.broadcastMealUpdate('updated', meal);
    }

    res.json({
      success: true,
      message: 'Meal updated successfully',
      data: meal
    });
  } catch (error) {
    console.error('Update meal error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update meal'
    });
  }
});

// DELETE /api/meals/:id - Delete meal (owner only)
router.delete('/:id', authenticateToken, requireOwner, [
  param('id').isMongoId().withMessage('Invalid meal ID')
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

    const meal = await Meal.findByIdAndDelete(req.params.id);

    if (!meal) {
      return res.status(404).json({
        success: false,
        message: 'Meal not found'
      });
    }

    // Broadcast meal deletion to all connected clients
    if (global.websocketService) {
      global.websocketService.broadcastMealUpdate('deleted', { _id: meal._id });
    }

    res.json({
      success: true,
      message: 'Meal deleted successfully'
    });
  } catch (error) {
    console.error('Delete meal error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete meal'
    });
  }
});

module.exports = router;