const { WebSocketServer } = require('ws');

class WebSocketService {
  constructor() {
    this.wss = null;
    this.clients = new Map(); // Map<WebSocket, {userId, role}>
  }

  initialize(server) {
    // Create WebSocket server
    this.wss = new WebSocketServer({ server });

    this.wss.on('connection', (ws, req) => {
      console.log('📡 New WebSocket connection established');

      ws.on('message', (message) => {
        try {
          const data = JSON.parse(message);
          
          if (data.type === 'auth') {
            // Authenticate client
            const userId = data.userId || data.token;
            const role = data.role || 'user';
            
            this.clients.set(ws, { userId, role });
            console.log(`✅ WebSocket authenticated: ${userId} (${role})`);
            
            ws.send(JSON.stringify({ 
              type: 'connected', 
              message: 'WebSocket authenticated',
              userId,
              role
            }));
          } else if (data.type === 'ping') {
            // Handle ping for keep-alive
            ws.send(JSON.stringify({ type: 'pong' }));
          }
        } catch (error) {
          console.error('WebSocket message error:', error);
        }
      });

      ws.on('close', () => {
        this.clients.delete(ws);
        console.log('📴 WebSocket connection closed');
      });

      ws.on('error', (error) => {
        console.error('❌ WebSocket error:', error);
        this.clients.delete(ws);
      });

      // Send initial connection message
      ws.send(JSON.stringify({ 
        type: 'connected', 
        message: 'Connected to WebSocket server' 
      }));
    });

    console.log('✅ WebSocket service initialized');
  }

  // Broadcast to all connected clients
  broadcast(event, data) {
    const message = JSON.stringify({ type: event, data });
    let sentCount = 0;

    this.clients.forEach((clientInfo, ws) => {
      try {
        if (ws.readyState === 1) { // WebSocket.OPEN
          ws.send(message);
          sentCount++;
        }
      } catch (error) {
        console.error('Error broadcasting to client:', error);
        this.clients.delete(ws);
      }
    });

    console.log(`📢 Broadcasted ${event} to ${sentCount} clients`);
    return sentCount;
  }

  // Send to specific user
  sendToUser(userId, event, data) {
    const message = JSON.stringify({ type: event, data });
    let sentCount = 0;

    this.clients.forEach((clientInfo, ws) => {
      if (clientInfo.userId === userId) {
        try {
          if (ws.readyState === 1) { // WebSocket.OPEN
            ws.send(message);
            sentCount++;
          }
        } catch (error) {
          console.error('Error sending to user:', error);
          this.clients.delete(ws);
        }
      }
    });

    if (sentCount > 0) {
      console.log(`📤 Sent ${event} to user ${userId}`);
    }
    return sentCount;
  }

  // Send to all users with specific role
  sendToRole(role, event, data) {
    const message = JSON.stringify({ type: event, data });
    let sentCount = 0;

    this.clients.forEach((clientInfo, ws) => {
      if (clientInfo.role === role) {
        try {
          if (ws.readyState === 1) { // WebSocket.OPEN
            ws.send(message);
            sentCount++;
          }
        } catch (error) {
          console.error('Error sending to role:', error);
          this.clients.delete(ws);
        }
      }
    });

    if (sentCount > 0) {
      console.log(`📤 Sent ${event} to ${sentCount} ${role}(s)`);
    }
    return sentCount;
  }

  // Broadcast meal updates to all clients (students and owners)
  broadcastMealUpdate(action, meal) {
    return this.broadcast('meal_update', {
      action, // 'created', 'updated', 'deleted'
      meal
    });
  }

  // Get connected clients count
  getConnectedCount() {
    return this.clients.size;
  }

  // Close all connections
  closeAll() {
    this.clients.forEach((clientInfo, ws) => {
      try {
        ws.close();
      } catch (error) {
        console.error('Error closing connection:', error);
      }
    });
    this.clients.clear();
  }
}

// Create singleton instance
const websocketService = new WebSocketService();

module.exports = websocketService;

