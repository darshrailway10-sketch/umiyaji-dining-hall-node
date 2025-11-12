# Dining Hall Management System - Backend API

A comprehensive Node.js + Express backend API for the Umiya Ji Dining Hall Management System. This backend provides complete CRUD operations for managing meals, orders, subscriptions, clients, attendance, bills, and notifications with real-time WebSocket support.

## 🚀 Features

- **RESTful API** with complete CRUD operations
- **JWT Authentication** with role-based access control
- **Real-time notifications** via WebSocket
- **MongoDB integration** with Mongoose ODM
- **Input validation** with express-validator
- **Security middleware** (Helmet, CORS, Rate limiting)
- **Comprehensive error handling**
- **Analytics and reporting**
- **Bill generation from attendance records**

## 📁 Project Structure

```
backend/
├── models/           # MongoDB models
│   ├── User.js       # User authentication
│   ├── Meal.js       # Menu items
│   ├── Order.js      # Food orders
│   ├── Subscription.js # Tiffin subscriptions
│   ├── Client.js     # Client management
│   ├── Attendance.js # Meal attendance tracking
│   ├── Bill.js       # Billing system
│   └── Notification.js # Real-time notifications
├── routes/           # API routes
│   ├── auth.js       # Authentication
│   ├── meals.js      # Menu management
│   ├── orders.js     # Order management
│   ├── subscriptions.js # Subscription management
│   ├── clients.js    # Client management
│   ├── attendance.js # Attendance tracking
│   ├── bills.js      # Billing system
│   ├── analytics.js  # Analytics and reporting
│   └── notifications.js # Notification system
├── middleware/       # Custom middleware
│   └── auth.js       # Authentication middleware
├── .env.example      # Environment variables template
├── package.json      # Dependencies and scripts
└── server.js         # Main server file
```

## 🛠️ Installation

1. **Clone the repository and navigate to backend directory**
   ```bash
   cd backend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` file with your configuration:
   ```env
   MONGODB_URI=mongodb://localhost:27017/dining_hall
   JWT_SECRET=your_super_secret_jwt_key
   JWT_EXPIRES_IN=7d
   PORT=8000
   NODE_ENV=development
   FRONTEND_URL=http://localhost:5173
   ```

4. **Start MongoDB**
   ```bash
   # Using MongoDB service
   sudo service mongod start
   
   # Or using Docker
   docker run -d -p 27017:27017 --name mongodb mongo:latest
   ```

5. **Start the server**
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   ```

## 🔐 Authentication

The API uses JWT-based authentication. Include the token in the Authorization header:

```http
Authorization: Bearer <your_jwt_token>
```

### User Roles

- **user**: Regular students/clients
- **owner**: Restaurant owners/admins with full access

## 📚 API Documentation

### Authentication Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "phone": "9876543210",
  "password": "password123",
  "role": "user" // or "owner"
}
```

#### Login User
```http
POST /api/auth/login
Content-Type: application/json

{
  "phone": "9876543210",
  "password": "password123"
}
```

#### Get Profile
```http
GET /api/auth/profile
Authorization: Bearer <token>
```

### Meals Endpoints

#### Get All Meals
```http
GET /api/meals
# Optional: ?type=breakfast|lunch|dinner
```

#### Get Specific Meal
```http
GET /api/meals/:id
```

#### Create Meal (Owner Only)
```http
POST /api/meals
Authorization: Bearer <owner_token>
Content-Type: application/json

{
  "name": "Paneer Tikka",
  "type": "lunch",
  "price": 150,
  "prepTime": "25 mins",
  "description": "Delicious paneer tikka"
}
```

#### Update Meal (Owner Only)
```http
PUT /api/meals/:id
Authorization: Bearer <owner_token>
Content-Type: application/json

{
  "name": "Paneer Tikka Masala",
  "price": 160,
  "prepTime": "30 mins"
}
```

#### Delete Meal (Owner Only)
```http
DELETE /api/meals/:id
Authorization: Bearer <owner_token>
```

### Orders Endpoints

#### Get All Orders
```http
GET /api/orders
# Optional: ?status=pending&date=2024-01-01
```

#### Create Order
```http
POST /api/orders
Authorization: Bearer <token>
Content-Type: application/json

{
  "studentName": "John Doe",
  "phone": "9876543210",
  "items": [
    {
      "mealName": "Paneer Tikka",
      "quantity": 2,
      "price": 150
    }
  ],
  "total": 300,
  "deliveryTime": "7:00 PM",
  "notes": "Extra spicy"
}
```

#### Update Order Status (Owner Only)
```http
PATCH /api/orders/:id/status
Authorization: Bearer <owner_token>
Content-Type: application/json

{
  "status": "ready" // pending, preparing, ready, completed, cancelled
}
```

### Clients Endpoints

#### Get All Clients
```http
GET /api/clients
```

#### Get Client by Phone
```http
GET /api/clients/phone/:phone
```

#### Create Client (Owner Only)
```http
POST /api/clients
Authorization: Bearer <owner_token>
Content-Type: application/json

{
  "name": "Jane Doe",
  "phone": "9876543211",
  "email": "jane@example.com",
  "address": {
    "street": "123 Main St",
    "city": "Ahmedabad",
    "state": "Gujarat",
    "pincode": "380001"
  }
}
```

### Attendance Endpoints

#### Get All Attendance
```http
GET /api/attendance
# Optional: ?studentPhone=9876543210&startDate=2024-01-01&endDate=2024-01-31
```

#### Get Student Attendance
```http
GET /api/attendance/student/:phone
# Optional: ?startDate=2024-01-01&endDate=2024-01-31
```

#### Record Attendance (Owner Only)
```http
POST /api/attendance
Authorization: Bearer <owner_token>
Content-Type: application/json

{
  "studentName": "John Doe",
  "studentPhone": "9876543210",
  "mealType": "lunch",
  "date": "2024-01-15",
  "price": 150
}
```

### Bills Endpoints

#### Get All Bills
```http
GET /api/bills
# Optional: ?studentPhone=9876543210&status=generated
```

#### Get Student Bills
```http
GET /api/bills/student/:phone
```

#### Generate Bill (Owner Only)
```http
POST /api/bills/generate
Authorization: Bearer <owner_token>
Content-Type: application/json

{
  "studentName": "John Doe",
  "studentPhone": "9876543210",
  "startDate": "2024-01-01",
  "endDate": "2024-01-31"
}
```

### Notifications Endpoints

#### Get User Notifications
```http
GET /api/notifications/user/:phone
# Optional: ?limit=20
```

#### Get Unread Count
```http
GET /api/notifications/count/:phone
```

#### Mark Notification as Read
```http
PATCH /api/notifications/:id/read
```

#### Send Notification (Owner Only)
```http
POST /api/notifications
Authorization: Bearer <owner_token>
Content-Type: application/json

{
  "studentPhone": "9876543210",
  "studentName": "John Doe",
  "title": "Order Ready",
  "message": "Your order is ready for pickup",
  "type": "order"
}
```

### Analytics Endpoints

#### Get Analytics Data
```http
GET /api/analytics
```

Returns comprehensive analytics including:
- Overview statistics (orders, meals, attendance, etc.)
- Orders by status
- Meals by type with average prices
- Revenue data (last 30 days)
- Top performing meals
- Attendance trends
- Bills by status

## 🔌 WebSocket Events

The backend supports real-time notifications via WebSocket. Connect to:

```javascript
const ws = new WebSocket('ws://localhost:8000');

// Authenticate with token
ws.send(JSON.stringify({
  type: 'auth',
  token: 'your_jwt_token',
  userId: 'user_phone_or_id'
}));

// Listen for notifications
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'notification') {
    console.log('New notification:', data.data);
  }
};
```

## 🔒 Security Features

- **JWT Authentication** with secure token generation
- **Password hashing** using bcrypt
- **Input validation** with express-validator
- **Rate limiting** to prevent abuse
- **CORS protection** with configurable origins
- **Helmet** for security headers
- **Role-based access control** (user/owner)

## 📊 Database Models

### User Model
- `name`: String (required)
- `email`: String (unique, optional)
- `phone`: String (required, unique, 10 digits)
- `password`: String (required, hashed)
- `role`: String (enum: 'user', 'owner')
- `isActive`: Boolean (default: true)

### Meal Model
- `name`: String (required)
- `type`: String (enum: 'breakfast', 'lunch', 'dinner')
- `price`: Number (required, non-negative)
- `prepTime`: String (required)
- `description`: String (optional)
- `available`: Boolean (default: true)

### Order Model
- `studentName`: String (required)
- `phone`: String (required)
- `items`: Array of meal items with quantity and price
- `total`: Number (required, non-negative)
- `status`: String (enum: 'pending', 'preparing', 'ready', 'completed', 'cancelled')
- `orderDate`: Date (default: now)
- `notes`: String (optional)

### Client Model
- `name`: String (required)
- `phone`: String (required, unique)
- `email`: String (optional)
- `address`: Object with street, city, state, pincode
- `status`: String (enum: 'active', 'inactive')

### Attendance Model
- `studentName`: String (required)
- `studentPhone`: String (required)
- `mealType`: String (enum: 'breakfast', 'lunch', 'dinner')
- `date`: Date (required)
- `price`: Number (required, non-negative)

### Bill Model
- `billNumber`: String (required, unique)
- `studentName`: String (required)
- `studentPhone`: String (required)
- `startDate`: Date (required)
- `endDate`: Date (required)
- `totalMeals`: Number (required, non-negative)
- `totalAmount`: Number (required, non-negative)
- `status`: String (enum: 'generated', 'sent', 'paid', 'overdue')
- `meals`: Array of meal details

### Notification Model
- `studentPhone`: String (required)
- `studentName`: String (required)
- `title`: String (required)
- `message`: String (required)
- `type`: String (enum: 'order', 'attendance', 'bill', 'subscription', 'menu', 'general')
- `read`: Boolean (default: false)
- `relatedId`: ObjectId (optional)
- `relatedModel`: String (optional)

## 🧪 Testing

Test the API endpoints using tools like Postman, curl, or Insomnia:

```bash
# Test health endpoint
curl http://localhost:8000/health

# Test authentication
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"phone":"9876543210","password":"password123"}'

# Test protected endpoint
curl http://localhost:8000/api/meals \
  -H "Authorization: Bearer <your_token>"
```

## 🚦 Error Handling

The API returns consistent error responses:

```json
{
  "success": false,
  "message": "Error description",
  "errors": ["validation error details"]
}
```

## 📈 Performance Features

- **Database indexing** on frequently queried fields
- **Pagination support** for large datasets
- **Efficient aggregation** for analytics
- **Connection pooling** with MongoDB
- **Rate limiting** to prevent abuse

## 🔧 Configuration

All configuration is handled through environment variables. See `.env.example` for all available options.

## 📝 License

This project is licensed under the MIT License.