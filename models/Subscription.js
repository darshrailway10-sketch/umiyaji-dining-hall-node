const mongoose = require('mongoose');

const subscriptionSchema = new mongoose.Schema({
  studentName: {
    type: String,
    required: [true, 'Student name is required'],
    trim: true
  },
  phone: {
    type: String,
    required: [true, 'Phone number is required'],
    match: [/^\d{10}$/, 'Please enter a valid 10-digit phone number']
  },
  plan: {
    type: String,
    required: [true, 'Plan type is required'],
    enum: ['weekly', 'monthly']
  },
  startDate: {
    type: Date,
    required: [true, 'Start date is required']
  },
  endDate: {
    type: Date,
    required: [true, 'End date is required']
  },
  price: {
    type: Number,
    required: [true, 'Price is required'],
    min: [0, 'Price cannot be negative']
  },
  status: {
    type: String,
    enum: ['active', 'paused', 'expired', 'cancelled'],
    default: 'active'
  },
  mealsIncluded: {
    type: Number,
    default: function() {
      return this.plan === 'weekly' ? 7 : 30;
    }
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Indexes for performance
subscriptionSchema.index({ phone: 1 });
subscriptionSchema.index({ status: 1 });
subscriptionSchema.index({ startDate: 1, endDate: 1 });

module.exports = mongoose.model('Subscription', subscriptionSchema);