const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  studentPhone: {
    type: String,
    required: [true, 'Student phone is required'],
    match: [/^\d{10}$/, 'Please enter a valid 10-digit phone number']
  },
  studentName: {
    type: String,
    required: [true, 'Student name is required'],
    trim: true
  },
  title: {
    type: String,
    required: [true, 'Notification title is required'],
    trim: true,
    maxlength: [100, 'Title cannot exceed 100 characters']
  },
  message: {
    type: String,
    required: [true, 'Notification message is required'],
    maxlength: [500, 'Message cannot exceed 500 characters']
  },
  type: {
    type: String,
    enum: ['order', 'attendance', 'bill', 'subscription', 'menu', 'general'],
    default: 'general'
  },
  read: {
    type: Boolean,
    default: false
  },
  relatedId: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'relatedModel'
  },
  relatedModel: {
    type: String,
    enum: ['Order', 'Attendance', 'Bill', 'Subscription', 'Meal', null],
    default: null
  },
  sentBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Indexes for performance
notificationSchema.index({ studentPhone: 1, read: 1 });
notificationSchema.index({ createdAt: -1 });
notificationSchema.index({ type: 1 });

module.exports = mongoose.model('Notification', notificationSchema);