const mongoose = require('mongoose');

const billSchema = new mongoose.Schema({
  billNumber: {
    type: String,
    required: [true, 'Bill number is required'],
    unique: true
  },
  studentName: {
    type: String,
    required: [true, 'Student name is required'],
    trim: true
  },
  studentPhone: {
    type: String,
    required: [true, 'Student phone is required'],
    match: [/^\d{10}$/, 'Please enter a valid 10-digit phone number']
  },
  startDate: {
    type: Date,
    required: [true, 'Start date is required']
  },
  endDate: {
    type: Date,
    required: [true, 'End date is required']
  },
  totalMeals: {
    type: Number,
    required: [true, 'Total meals count is required'],
    min: [0, 'Total meals cannot be negative']
  },
  totalAmount: {
    type: Number,
    required: [true, 'Total amount is required'],
    min: [0, 'Total amount cannot be negative']
  },
  status: {
    type: String,
    enum: ['generated', 'sent', 'paid', 'overdue'],
    default: 'generated'
  },
  meals: [{
    date: Date,
    type: String,
    price: Number
  }],
  generatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Indexes for performance
billSchema.index({ studentPhone: 1 });
billSchema.index({ billNumber: 1 });
billSchema.index({ status: 1 });
billSchema.index({ startDate: 1, endDate: 1 });

module.exports = mongoose.model('Bill', billSchema);