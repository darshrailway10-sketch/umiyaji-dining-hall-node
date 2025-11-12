const mongoose = require('mongoose');

const mealSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Meal name is required'],
    trim: true,
    maxlength: [100, 'Meal name cannot exceed 100 characters']
  },
  type: {
    type: String,
    required: [true, 'Meal type is required'],
    enum: ['breakfast', 'lunch', 'dinner'],
    default: 'lunch'
  },
  price: {
    type: Number,
    required: [true, 'Price is required'],
    min: [0, 'Price cannot be negative']
  },
  prepTime: {
    type: String,
    required: [true, 'Preparation time is required'],
    maxlength: [50, 'Preparation time cannot exceed 50 characters']
  },
  description: {
    type: String,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  available: {
    type: Boolean,
    default: true
  },
  image: {
    type: String,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Indexes for performance
mealSchema.index({ type: 1 });
mealSchema.index({ available: 1 });
mealSchema.index({ name: 'text', description: 'text' });

module.exports = mongoose.model('Meal', mealSchema);