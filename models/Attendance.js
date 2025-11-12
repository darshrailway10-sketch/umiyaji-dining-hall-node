const mongoose = require('mongoose');

const attendanceSchema = new mongoose.Schema({
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
  mealType: {
    type: String,
    required: [true, 'Meal type is required'],
    enum: ['breakfast', 'lunch', 'dinner']
  },
  date: {
    type: Date,
    required: [true, 'Date is required']
  },
  price: {
    type: Number,
    required: [true, 'Price is required'],
    min: [0, 'Price cannot be negative']
  },
  recordedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Compound index for efficient queries
attendanceSchema.index({ studentPhone: 1, date: 1 });
attendanceSchema.index({ date: 1, mealType: 1 });
attendanceSchema.index({ studentPhone: 1, date: 1, mealType: 1 });

module.exports = mongoose.model('Attendance', attendanceSchema);