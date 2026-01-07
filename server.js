const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');
require('dotenv').config();

const app = express();
// Email & SMS Setup
const nodemailer = require('nodemailer');
const twilio = require('twilio');

// Email Configuration
const emailTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

// SMS Configuration (optional)
let twilioClient;
if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
  twilioClient = twilio(
    process.env.TWILIO_ACCOUNT_SID,
    process.env.TWILIO_AUTH_TOKEN
  );
}

// Notification Functions
async function sendEmailNotification(to, subject, message) {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: to,
      subject: subject,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #ef4444 0%, #f97316 100%); padding: 20px; text-center;">
            <h1 style="color: white; margin: 0;">🚨 SafeLink Alert</h1>
          </div>
          <div style="padding: 20px; background: #f9f9f9;">
            <h2 style="color: #333;">${subject}</h2>
            <p style="color: #666; font-size: 16px; line-height: 1.6;">${message}</p>
          </div>
        </div>
      `
    };

    await emailTransporter.sendMail(mailOptions);
    console.log('✅ Email sent to:', to);
    return true;
  } catch (error) {
    console.error('❌ Email error:', error.message);
    return false;
  }
}

async function sendSMSNotification(to, message) {
  if (!twilioClient) {
    console.log('ℹ️ SMS skipped - Twilio not configured');
    return false;
  }
  
  try {
    await twilioClient.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: to
    });
    console.log('✅ SMS sent to:', to);
    return true;
  } catch (error) {
    console.error('❌ SMS error:', error.message);
    return false;
  }
}
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:3001',
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/safelink')
.then(() => console.log('✅ MongoDB Connected Successfully'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// ==================== SCHEMAS ====================

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  role: { 
    type: String, 
    enum: ['user', 'volunteer', 'admin', 'hospital'],
    default: 'user' 
  },
  bloodGroup: String,
  address: String,
  isAvailable: { type: Boolean, default: true },
  location: {
    type: {
      type: String,
      enum: ['Point']
    },
    coordinates: {
      type: [Number]
    }
  },
  createdAt: { type: Date, default: Date.now }
});

userSchema.index({ location: '2dsphere' }, { sparse: true });  // Make index sparse

// Alert Schema
const alertSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  emergencyType: { 
    type: String, 
    required: true,
    enum: ['medical', 'accident', 'fire', 'flood', 'violence', 'other']
  },
  description: String,
  location: {
    type: { type: String, default: 'Point' },
    coordinates: { type: [Number], required: true } // [longitude, latitude]
  },
  address: String,
  status: { 
    type: String, 
    enum: ['active', 'assigned', 'resolved', 'cancelled'],
    default: 'active' 
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'high'
  },
  assignedTo: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  contactNumber: String,
  createdAt: { type: Date, default: Date.now },
  resolvedAt: Date,
  notes: String
});

alertSchema.index({ location: '2dsphere' });

// Hospital Schema
const hospitalSchema = new mongoose.Schema({
  name: { type: String, required: true },
  address: { type: String, required: true },
  phone: { type: String, required: true },
  email: String,
  type: { 
    type: String, 
    enum: ['government', 'private', 'clinic'],
    default: 'government' 
  },
  facilities: [String],
  emergencyAvailable: { type: Boolean, default: true },
  location: {
    type: { type: String, default: 'Point' },
    coordinates: { type: [Number], required: true }
  },
  rating: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

hospitalSchema.index({ location: '2dsphere' });

const User = mongoose.model('User', userSchema);
const Alert = mongoose.model('Alert', alertSchema);
const Hospital = mongoose.model('Hospital', hospitalSchema);

// ==================== MIDDLEWARE ====================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'safelink-secret-key', (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin' && req.user.role !== 'volunteer') {
    return res.status(403).json({ message: 'Admin or volunteer access required' });
  }
  next();
};

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password, role, bloodGroup, address } = req.body;

    if (!name || !email || !phone || !password) {
      return res.status(400).json({ message: 'All fields required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      phone,
      password: hashedPassword,
      role: role || 'user',
      bloodGroup,
      address
    });

    await user.save();

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET || 'safelink-secret-key',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        phone: user.phone
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET || 'safelink-secret-key',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        phone: user.phone
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== ALERT ROUTES ====================

// Create Emergency Alert
app.post('/api/alerts', authenticateToken, async (req, res) => {
  try {
    const { emergencyType, description, latitude, longitude, address, contactNumber } = req.body;

    if (!emergencyType || !latitude || !longitude) {
      return res.status(400).json({ message: 'Emergency type and location required' });
    }

    const user = await User.findById(req.user.id);

    const alert = new Alert({
      userId: req.user.id,
      emergencyType,
      description,
      location: {
        type: 'Point',
        coordinates: [longitude, latitude]
      },
      address,
      contactNumber: contactNumber || user.phone,
      priority: emergencyType === 'medical' || emergencyType === 'accident' ? 'critical' : 'high'
    });

    await alert.save();
    await alert.populate('userId', 'name phone email');

    // 📧 Send confirmation email to user
    await sendEmailNotification(
      user.email,
      'Emergency Alert Created',
      `Your ${emergencyType} emergency alert has been created successfully. Our team has been notified and help is on the way. Stay safe!`
    );

    // 📱 Send confirmation SMS to user (if configured)
    await sendSMSNotification(
      user.phone,
      `SafeLink Alert: Your ${emergencyType} emergency has been reported. Help is on the way. Stay calm and safe.`
    );

    // 🔔 Notify nearby volunteers via email
    const nearbyVolunteers = await User.find({
      role: { $in: ['volunteer', 'admin'] },
      isAvailable: true,
      location: {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: [longitude, latitude]
          },
          $maxDistance: 10000 // 10km
        }
      }
    }).limit(5);

    // Send notifications to volunteers
    for (const volunteer of nearbyVolunteers) {
      await sendEmailNotification(
        volunteer.email,
        'New Emergency Alert Nearby',
        `A ${emergencyType} emergency has been reported near your location. Please check the dashboard to assist.`
      );
    }

    // Emit real-time alert
    io.emit('newAlert', alert);

    res.status(201).json({
      message: 'Emergency alert created and notifications sent',
      alert
    });
  } catch (error) {
    console.error('Create alert error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get All Alerts (Admin/Volunteer)
app.get('/api/alerts', authenticateToken, async (req, res) => {
  try {
    const { status, emergencyType } = req.query;
    let query = {};

    if (req.user.role === 'user') {
      query.userId = req.user.id;
    }

    if (status) query.status = status;
    if (emergencyType) query.emergencyType = emergencyType;

    const alerts = await Alert.find(query)
      .populate('userId', 'name phone email')
      .populate('assignedTo', 'name phone role')
      .sort({ createdAt: -1 });

    res.json({ alerts, count: alerts.length });
  } catch (error) {
    console.error('Get alerts error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Nearby Alerts (for volunteers)
app.get('/api/alerts/nearby', authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude, radius = 10000 } = req.query; // radius in meters (default 10km)

    if (!latitude || !longitude) {
      return res.status(400).json({ message: 'Location required' });
    }

    const alerts = await Alert.find({
      status: { $in: ['active', 'assigned'] },
      location: {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: [parseFloat(longitude), parseFloat(latitude)]
          },
          $maxDistance: parseInt(radius)
        }
      }
    })
    .populate('userId', 'name phone email')
    .populate('assignedTo', 'name phone role')
    .limit(20);

    res.json({ alerts, count: alerts.length });
  } catch (error) {
    console.error('Nearby alerts error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Alert Status
app.put('/api/alerts/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status, notes, assignedTo } = req.body;

    const alert = await Alert.findById(req.params.id);
    if (!alert) {
      return res.status(404).json({ message: 'Alert not found' });
    }

    if (status) alert.status = status;
    if (notes) alert.notes = notes;
    if (assignedTo) alert.assignedTo = assignedTo;
    if (status === 'resolved') alert.resolvedAt = new Date();

    await alert.save();
    await alert.populate('userId assignedTo');

    // Emit real-time update
    io.emit('alertUpdated', alert);

    res.json({ message: 'Alert updated', alert });
  } catch (error) {
    console.error('Update alert error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Assign Volunteer to Alert
app.post('/api/alerts/:id/assign', authenticateToken, async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id);
    if (!alert) {
      return res.status(404).json({ message: 'Alert not found' });
    }

    if (!alert.assignedTo.includes(req.user.id)) {
      alert.assignedTo.push(req.user.id);
      alert.status = 'assigned';
      await alert.save();
      await alert.populate('userId assignedTo');

      io.emit('alertUpdated', alert);
    }

    res.json({ message: 'Assigned to alert', alert });
  } catch (error) {
    console.error('Assign alert error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== HOSPITAL ROUTES ====================

// Get Nearby Hospitals
app.get('/api/hospitals/nearby', async (req, res) => {
  try {
    const { latitude, longitude, radius = 10000 } = req.query;

    if (!latitude || !longitude) {
      return res.status(400).json({ message: 'Location required' });
    }

    const hospitals = await Hospital.find({
      emergencyAvailable: true,
      location: {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: [parseFloat(longitude), parseFloat(latitude)]
          },
          $maxDistance: parseInt(radius)
        }
      }
    }).limit(10);

    res.json({ hospitals, count: hospitals.length });
  } catch (error) {
    console.error('Nearby hospitals error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add Hospital (Admin only)
app.post('/api/hospitals', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, address, phone, email, type, facilities, latitude, longitude } = req.body;

    const hospital = new Hospital({
      name,
      address,
      phone,
      email,
      type,
      facilities,
      location: {
        type: 'Point',
        coordinates: [longitude, latitude]
      }
    });

    await hospital.save();
    res.status(201).json({ message: 'Hospital added', hospital });
  } catch (error) {
    console.error('Add hospital error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== VOLUNTEER ROUTES ====================

// Get Available Volunteers Nearby
app.get('/api/volunteers/nearby', authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude, radius = 10000 } = req.query;

    if (!latitude || !longitude) {
      return res.status(400).json({ message: 'Location required' });
    }

    const volunteers = await User.find({
      role: { $in: ['volunteer', 'admin'] },
      isAvailable: true,
      location: {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: [parseFloat(longitude), parseFloat(latitude)]
          },
          $maxDistance: parseInt(radius)
        }
      }
    }).select('name phone email role').limit(10);

    res.json({ volunteers, count: volunteers.length });
  } catch (error) {
    console.error('Nearby volunteers error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Volunteer Location
app.put('/api/volunteers/location', authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude, isAvailable } = req.body;

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (latitude && longitude) {
      user.location = {
        type: 'Point',
        coordinates: [longitude, latitude]
      };
    }

    if (isAvailable !== undefined) {
      user.isAvailable = isAvailable;
    }

    await user.save();
    res.json({ message: 'Location updated', user });
  } catch (error) {
    console.error('Update location error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


app.get('/api/nearby-hospitals', async (req, res) => {
  const { lat, lng } = req.query;

  const url = `https://maps.googleapis.com/maps/api/place/nearbysearch/json
  ?location=${lat},${lng}
  &radius=3000
  &type=hospital
  &key=${process.env.GOOGLE_API_KEY}`;

  const response = await fetch(url);
  const data = await response.json();
  res.json(data.results);
});


// ==================== STATS ====================

app.get('/api/stats', authenticateToken, isAdmin, async (req, res) => {
  try {
    const totalAlerts = await Alert.countDocuments();
    const activeAlerts = await Alert.countDocuments({ status: 'active' });
    const resolvedAlerts = await Alert.countDocuments({ status: 'resolved' });
    const totalVolunteers = await User.countDocuments({ role: 'volunteer' });
    const availableVolunteers = await User.countDocuments({ role: 'volunteer', isAvailable: true });

    res.json({
      totalAlerts,
      activeAlerts,
      resolvedAlerts,
      totalVolunteers,
      availableVolunteers
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== SOCKET.IO ====================

io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);

  socket.on('joinRoom', (role) => {
    if (role === 'admin' || role === 'volunteer') {
      socket.join('responders');
      console.log(`${socket.id} joined responders room`);
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'SafeLink API is running' });
});

app.get('/', (req, res) => {
  res.json({ 
    message: 'SafeLink Emergency Alert System API',
    version: '1.0.0'
  });
});

// Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 SafeLink Server running on port ${PORT}`);
});

// Emergency Guides Route
app.get('/api/emergency-guides', (req, res) => {
  const guides = [
    {
      id: 1,
      type: 'medical',
      title: 'Medical Emergency',
      icon: '🏥',
      color: '#ef4444',
      steps: [
        'Stay calm and assess the situation',
        'Call emergency services immediately (112 or 108)',
        'Check if the person is breathing',
        'Perform CPR if trained',
        'Stop any bleeding',
        'Keep person warm',
        'Wait for help'
      ],
      importantNumbers: [
        { name: 'Ambulance', number: '108' },
        { name: 'Emergency', number: '112' }
      ]
    },
    {
      id: 2,
      type: 'accident',
      title: 'Road Accident',
      icon: '🚗',
      color: '#f97316',
      steps: [
        'Ensure your safety first',
        'Turn on hazard lights',
        'Call emergency (112)',
        'Do not move injured persons',
        'Provide first aid if trained'
      ],
      importantNumbers: [
        { name: 'Police', number: '100' },
        { name: 'Ambulance', number: '108' }
      ]
    }
    // Add more guide types from the artifact
  ];

  res.json({ guides });
});

/// Emergency Guides Route
app.get('/api/emergency-guides', (req, res) => {
  const guides = [
    {
      id: 1,
      type: 'medical',
      title: 'Medical Emergency',
      icon: '🏥',
      color: '#ef4444',
      steps: [
        'Stay calm and assess the situation',
        'Call emergency services immediately (112 or 108)',
        'Check if the person is breathing',
        'Perform CPR if trained',
        'Stop any bleeding',
        'Keep person warm',
        'Wait for help'
      ],
      importantNumbers: [
        { name: 'Ambulance', number: '108' },
        { name: 'Emergency', number: '112' }
      ]
    },
    {
      id: 2,
      type: 'accident',
      title: 'Road Accident',
      icon: '🚗',
      color: '#f97316',
      steps: [
        'Ensure your safety first',
        'Turn on hazard lights',
        'Call emergency (112)',
        'Do not move injured persons',
        'Provide first aid if trained'
      ],
      importantNumbers: [
        { name: 'Police', number: '100' },
        { name: 'Ambulance', number: '108' }
      ]
    }
    // Add more guide types from the artifact
  ];

  res.json({ guides });
});

// About Route
app.get('/api/about', (req, res) => {
  const about = {
    mission: 'To provide rapid emergency response through community-driven support.',
    vision: 'A world where help is just a click away.',
    features: [
      {
        icon: '🚨',
        title: 'One-Click Alert',
        description: 'Send emergency alerts instantly'
      },
      {
        icon: '📱',
        title: 'Instant Notifications',
        description: 'Get SMS and email updates'
      }
    ],
    stats: {
      users: '10,000+',
      volunteers: '2,500+',
      alertsResolved: '15,000+',
      responseTime: '< 5 mins'
    },
    contact: {
      email: 'support@safelink.com',
      phone: '1800-SAFELINK',
      address: 'India'
    }
  };

  res.json(about);
});