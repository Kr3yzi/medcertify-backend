require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const winston = require('winston');
const { ethers } = require('ethers');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { body, validationResult } = require('express-validator');
const axios = require('axios');
const pinataSDK = require('@pinata/sdk');
const crypto = require('crypto');


// Initialize Express app
const app = express();

// Security middleware
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        "font-src": ["'self'", "https://fonts.gstatic.com"],
        "img-src": ["'self'", "data:", "https://ipfs.io", "https://gateway.pinata.cloud", "https://cloudflare-ipfs.com"],
        "connect-src": ["'self'", "https://ipfs.io", "https://gateway.pinata.cloud", "https://cloudflare-ipfs.com"],
      },
    },
  })
);
app.use(express.json({ limit: '10kb' })); // Limit payload size
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    const allowed = process.env.ALLOWED_ORIGINS?.split(',').map(o => o.trim());
    if (allowed && allowed.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true, 
  methods: ['GET', 'POST', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
  logger.info('Using test API token for development');
}

app.use(morgan('combined'));

// Store nonces (in production, use Redis or similar)
const nonces = new Map();

// Generate nonce endpoint
app.post('/api/generate-nonce', async (req, res) => {
  try {
    const { address } = req.body;
    if (!ethers.isAddress(address)) {
      return res.status(400).json({ error: 'Invalid Ethereum address' });
    }

    const nonce = Math.floor(Math.random() * 1000000).toString();
    nonces.set(address.toLowerCase(), nonce);

    res.json({ nonce });
  } catch (error) {
    logger.error('Error generating nonce:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify signature endpoint
app.post('/api/verify-signature', async (req, res) => {
  try {
    const { address, signature, nonce } = req.body;
    
    if (!ethers.isAddress(address)) {
      return res.status(400).json({ error: 'Invalid Ethereum address' });
    }

    const storedNonce = nonces.get(address.toLowerCase());
    if (!storedNonce || storedNonce !== nonce) {
      return res.status(400).json({ error: 'Invalid nonce' });
    }

    const message = `Sign this message to authenticate with the Health Certificate System. Nonce: ${nonce}`;
    const recoveredAddress = ethers.verifyMessage(message, signature);

    if (recoveredAddress.toLowerCase() !== address.toLowerCase()) {
      return res.status(401).json({ error: 'Invalid signature' });
    }

    // Clear used nonce
    nonces.delete(address.toLowerCase());

    // Generate JWT
    const token = jwt.sign(
      { address: address.toLowerCase() },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token });
  } catch (error) {
    logger.error('Error verifying signature:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// JWT verification middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Initialize ethers provider and contract
const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
const contract = new ethers.Contract(
  process.env.HEALTH_CERTIFICATE_RBAC_ADDRESS,
  [
    "function isRole(address account, bytes32 role) view returns (bool)",
    "function assignRole(address account, bytes32 role)",
    "function revokeRole(address account, bytes32 role)",
    "function issueCertificate(address patient, bytes32 certHash)",
    "function getCertificates(address patient) view returns (bytes32[])"
  ],
  provider
);

// Role constants
const ROLES = {
  ADMIN: ethers.keccak256(ethers.toUtf8Bytes('ADMIN_ROLE')),
  RECEPTIONIST: ethers.keccak256(ethers.toUtf8Bytes('RECEPTIONIST_ROLE')),
  NURSE: ethers.keccak256(ethers.toUtf8Bytes('NURSE_ROLE')),
  DOCTOR: ethers.keccak256(ethers.toUtf8Bytes('DOCTOR_ROLE')),
  PATIENT: ethers.keccak256(ethers.toUtf8Bytes('PATIENT_ROLE'))
};

// Protected check-role endpoint
app.get('/api/check-role', verifyToken, async (req, res) => {
  try {
    const { address } = req.user;
    const roles = {};

    // Check on-chain roles
    for (const [roleName, roleHash] of Object.entries(ROLES)) {
      roles[roleName.toLowerCase()] = await contract.isRole(address, roleHash);
    }
    // Always check if patient in MongoDB, regardless of on-chain roles
      const patient = await Patient.findOne({ address: address.toLowerCase() });
      roles.patient = !!patient;

    res.json({ address, roles });
  } catch (error) {
    logger.error('Error checking role:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add UserRole model for tracking current user-role assignments
const UserRole = mongoose.model('UserRole', new mongoose.Schema({
  address: { type: String, required: true, index: true },
  role: { type: String, required: true },
  assignedAt: { type: Date, default: Date.now },
  assignedBy: { type: String },
  active: { type: Boolean, default: true }
}));

app.post('/api/assign-role', verifyToken, async (req, res) => {
  try {
    const address = sanitizeAddress(req.body.address);
    const role = sanitizeRole(req.body.role);
    
    if (!address) {
      return res.status(400).json({ error: 'Invalid Ethereum address' });
    }
    if (!role) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const roleHash = ROLES[role];
    const signer = new ethers.Wallet(process.env.ADMIN_PRIVATE_KEY, provider);
    const contractWithSigner = contract.connect(signer);
    const tx = await contractWithSigner.assignRole(address, roleHash);
    await tx.wait();
    await AuditLog.create({
      type: 'ACTION',
      action: 'assign_role',
      role: 'admin',
      address: req.user.address,
      target: address,
      assignedRole: role,
      timestamp: new Date(),
      message: `Admin assigned role ${role} to ${address}`
    });
    // Upsert UserRole in MongoDB
    await UserRole.findOneAndUpdate(
      { address, role },
      { address, role, assignedAt: new Date(), assignedBy: req.user.address, active: true },
      { upsert: true, new: true }
    );
    res.json({ success: true, transactionHash: tx.hash });
  } catch (error) {
    logger.error('Error assigning role:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/revoke-role', verifyToken, async (req, res) => {
  try {
    const address = sanitizeAddress(req.body.address);
    const role = sanitizeRole(req.body.role);
    
    if (!address) {
      return res.status(400).json({ error: 'Invalid Ethereum address' });
    }
    if (!role) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const roleHash = ROLES[role];
    const signer = new ethers.Wallet(process.env.ADMIN_PRIVATE_KEY, provider);
    const contractWithSigner = contract.connect(signer);
    const tx = await contractWithSigner.revokeRole(address, roleHash);
    await tx.wait();
    await AuditLog.create({
      type: 'ACTION',
      action: 'revoke_role',
      role: 'admin',
      address: req.user.address,
      target: address,
      revokedRole: role,
      timestamp: new Date(),
      message: `Admin revoked role ${role} from ${address}`
    });
    // Remove or mark UserRole as inactive in MongoDB
    await UserRole.findOneAndUpdate(
      { address, role },
      { active: false },
      { new: true }
    );
    res.json({ success: true, transactionHash: tx.hash });
  } catch (error) {
    logger.error('Error revoking role:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add HealthCertificate model after mongoose.connect
mongoose.connect(process.env.MONGODB_URI);

// Define TestSchema for subdocuments
const TestSchema = new mongoose.Schema({
  testType: String,
  purpose: String,
  orderedBy: String,
  status: String,
  resultCid: String
}, { _id: true });

// Define DiagnosisSchema for subdocuments
const DiagnosisSchema = new mongoose.Schema({
  cid: String,
  timestamp: Date,
  doctorAddress: String
}, { _id: true });

const Patient = mongoose.model('Patient', new mongoose.Schema({
  address: { type: String, required: true, unique: true },
  demographics: Object,
  vitals: Array,
  tests: [TestSchema],
  diagnosis: [DiagnosisSchema] // <-- use subdocument schema!
}));

const HealthCertificate = mongoose.model('HealthCertificate', new mongoose.Schema({
  patient: { type: String, required: true },           // Ethereum address
  issuedBy: { type: String, required: true },          // Doctor's address
  certType: { type: String, required: true },          // e.g. 'COVID', 'HIV'
  certHash: { type: String, required: true },          // Blockchain hash
  ipfsCid: { type: String },                           // IPFS file hash
  issuedAt: { type: Date, default: Date.now },
  signature: { type: String }, 
  certified: { type: Boolean, default: false },
  transactionHash: { type: String }
}));

// Add EncryptionKey schema
const EncryptionKey = mongoose.model('EncryptionKey', new mongoose.Schema({
  testId: { type: mongoose.Schema.Types.ObjectId, required: true },
  patientAddress: { type: String, required: true },
  encryptedDek: { type: String, required: true },  // Encrypted Data Encryption Key
  iv: { type: String, required: true },           // IV for DEK encryption
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  type: { type: String, required: true },
  certType: { type: String, required: true }
}));

// Middleware: role check
function requireRole(role) {
  return async (req, res, next) => {
    const address = req.user.address;
    const roleHash = ROLES[role.toUpperCase()];
    if (!roleHash) return res.status(400).json({ error: 'Invalid role' });
    try {
      const hasRole = await contract.isRole(address, roleHash);
      if (!hasRole) return res.status(403).json({ error: 'Forbidden: insufficient role' });
      next();
    } catch (err) {
      logger.error('Role check failed:', err);
      res.status(500).json({ error: 'Role check failed' });
    }
  };
}

function requireAnyRole(...roles) {
  return async (req, res, next) => {
    const address = req.user.address;
    try {
      for (const role of roles) {
        const roleHash = ROLES[role.toUpperCase()];
        if (!roleHash) return res.status(400).json({ error: 'Invalid role' });
        if (await contract.isRole(address, roleHash)) return next();
      }
      return res.status(403).json({ error: 'Forbidden: insufficient role' });
    } catch (err) {
      logger.error('Role check failed:', err);
      res.status(500).json({ error: 'Role check failed' });
    }
  };
}

function encryptDemographics(demographics, masterKey) {
  // 1. Convert demographics to string
  const data = Buffer.from(JSON.stringify(demographics), 'utf8');
  // 2. Generate random 32-byte DEK
  const dek = crypto.randomBytes(32);
  // 3. Encrypt demographics with AES-256-GCM
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
  let encrypted = cipher.update(data);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const tag = cipher.getAuthTag();
  // 4. Encrypt DEK with master key (KEK, AES-256-GCM)
  const dekIv = crypto.randomBytes(12);
  const kek = Buffer.from(masterKey, 'hex');
  const dekCipher = crypto.createCipheriv('aes-256-gcm', kek, dekIv);
  let encryptedDek = dekCipher.update(dek);
  encryptedDek = Buffer.concat([encryptedDek, dekCipher.final()]);
  const dekTag = dekCipher.getAuthTag();
  // 5. Return envelope
  return {
    encryptedData: encrypted.toString('base64'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    encryptionKey: {
      encryptedDek: encryptedDek.toString('base64'),
      dekIv: dekIv.toString('hex'),
      dekTag: dekTag.toString('hex')
    }
  };
}

function decryptDemographics(encrypted, masterKey) {
  if (!encrypted || !encrypted.encryptedData) return null;
  // 1. Decrypt DEK
  const kek = Buffer.from(masterKey, 'hex');
  const dekIv = Buffer.from(encrypted.encryptionKey.dekIv, 'hex');
  const dekTag = Buffer.from(encrypted.encryptionKey.dekTag, 'hex');
  const encryptedDek = Buffer.from(encrypted.encryptionKey.encryptedDek, 'base64');
  const dekDecipher = crypto.createDecipheriv('aes-256-gcm', kek, dekIv);
  dekDecipher.setAuthTag(dekTag);
  let dek = dekDecipher.update(encryptedDek);
  dek = Buffer.concat([dek, dekDecipher.final()]);
  // 2. Decrypt demographics
  const iv = Buffer.from(encrypted.iv, 'hex');
  const tag = Buffer.from(encrypted.tag, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', dek, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(Buffer.from(encrypted.encryptedData, 'base64'));
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return JSON.parse(decrypted.toString('utf8'));
}

// Add AuditLog model for audit/action logs
const AuditLog = mongoose.model('AuditLog', new mongoose.Schema({
  type: String,
  action: String,
  role: String,
  address: String,
  target: String,
  timestamp: { type: Date, default: Date.now },
  message: String,
  extra: Object
}));

// POST /api/register-patient (Receptionist)
app.post('/api/register-patient',
  verifyToken,
  requireRole('RECEPTIONIST'),
  body('address').isString(),
  body('demographics').isObject(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    try {
      const { address, demographics } = req.body;
      const encryptedDemographics = encryptDemographics(demographics, process.env.MASTER_KEY);
      const patient = await Patient.findOneAndUpdate(
        { address: address.toLowerCase() },
        { demographics: encryptedDemographics },
        { upsert: true, new: true }
      );
      await AuditLog.create({
        type: 'ACTION',
        action: 'register_patient',
        role: 'receptionist',
        address: req.user.address,
        target: address,
        timestamp: new Date(),
        message: `Receptionist registered patient ${address}`
      });
      res.json({ success: true, patient });
    } catch (err) {
      logger.error('Register patient error:', err);
      res.status(500).json({ error: 'Failed to register patient' });
    }
  }
);

// PATCH /api/patients/:id/vitals (Nurse)
app.patch('/api/patients/:id/vitals',
  verifyToken,
  requireRole('NURSE'),
  [
    body('height').isFloat({ min: 0 }).withMessage('Height must be a positive number'),
    body('weight').isFloat({ min: 0 }).withMessage('Weight must be a positive number'),
    body('bmi').isFloat({ min: 0 }).withMessage('BMI must be a positive number'),
    body('bloodPressure').matches(/^[0-9]{2,3}\/[0-9]{2,3}$/).withMessage('Blood pressure must be in format systolic/diastolic (e.g., 120/80)'),
    body('heartRate').isInt({ min: 0, max: 250 }).withMessage('Heart rate must be between 0 and 250'),
    body('temperature').isFloat({ min: 35, max: 42 }).withMessage('Temperature must be between 35 and 42'),
    body('respiratoryRate').isInt({ min: 0, max: 60 }).withMessage('Respiratory rate must be between 0 and 60'),
 ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const address = req.params.id.toLowerCase();
      const vitalsData = {
        ...req.body,
        timestamp: new Date()
      };

      const patient = await Patient.findOneAndUpdate(
        { address },
        { $push: { vitals: vitalsData } },
        { new: true }
      );

      if (!patient) {
        return res.status(404).json({ error: 'Patient not found' });
      }

      await AuditLog.create({
        type: 'ACTION',
        action: 'update_vitals',
        role: 'nurse',
        address: req.user.address,
        target: address,
        timestamp: new Date(),
        message: `Nurse updated vitals for patient ${address}`
      });
      res.json({ 
        success: true, 
        vitals: patient.vitals[patient.vitals.length - 1] 
      });
    } catch (err) {
      logger.error('Update vitals error:', err);
      res.status(500).json({ error: 'Failed to update vitals' });
    }
  }
);
// GET /api/patient/verify
app.get('/api/patient/verify', verifyToken, async (req, res) => {
  try {
    const { address } = req.user;
    const patient = await Patient.findOne({ address: address.toLowerCase() });
    res.json({ isRegistered: !!patient });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/patients/:id/vitals
app.get('/api/patients/:id/vitals',
  verifyToken,
  allowSelfOrRoles('NURSE', 'DOCTOR', 'ADMIN'),
  async (req, res) => {
    try {
      const address = req.params.id.toLowerCase();
      const patient = await Patient.findOne({ address });
      if (!patient) {
        return res.status(404).json({ error: 'Patient not found' });
      }
      // Sort vitals by timestamp in descending order (most recent first)
      const sortedVitals = patient.vitals.sort((a, b) => b.timestamp - a.timestamp);
      res.json({ 
        success: true,
        vitals: sortedVitals
      });
    } catch (err) {
      logger.error('Vitals access error:', err);
      res.status(500).json({ error: 'Failed to fetch vitals' });
    }
  }
);

// GET /api/patients/:id/tests - List all tests for a patient (minimal metadata)
app.get('/api/patients/:id/tests',
  verifyToken,
  allowSelfOrRoles('RECEPTIONIST', 'NURSE', 'DOCTOR', 'ADMIN'),
  async (req, res) => {
    try {
      const address = req.params.id.toLowerCase();
      const patient = await Patient.findOne({ address });
      if (!patient) return res.status(404).json({ error: 'Patient not found' });
      // Return minimal metadata and result availability
      const tests = (patient.tests || []).map(t => ({
        _id: t._id,
        testType: t.testType,
        purpose: t.purpose,
        orderedBy: t.orderedBy,
        status: t.status,
        timestamp: t.timestamp,
        hasResults: !!t.resultCid
      }));
      res.json({ tests });
    } catch (err) {
      logger.error('Fetch tests error:', err);
      res.status(500).json({ error: 'Failed to fetch tests' });
    }
  }
);

// GET /api/patients/:id/tests/:testId - Get a single test with decoded result from IPFS
app.get('/api/patients/:id/tests/:testId', verifyToken, requireAnyRole('DOCTOR', 'ADMIN'), async (req, res) => {
  try {
    const address = req.params.id.toLowerCase();
    const testId = req.params.testId;
    const patientDoc = await Patient.findOne({ address });
    if (!patientDoc) return res.status(404).json({ error: 'Patient not found' });
    const test = (patientDoc.tests || []).find(t => t._id.toString() === testId);
    if (!test) return res.status(404).json({ error: 'Test not found' });

    let resultData = null;
    let resultDataError = null;

    if (test.resultCid) {
      try {
        const axios = require('axios');
        const response = await axios.get(`https://gateway.pinata.cloud/ipfs/${test.resultCid}`);
    const encryptedData = response.data;

    // Try to decrypt using your decryptData function
    try {
      // test._id and address are required for key lookup
      resultData = await decryptData(encryptedData, test._id, address);
    } catch (decryptErr) {
      resultDataError = 'Failed to fetch or decrypt result data from IPFS.';
      console.error('Decryption error:', decryptErr);
        }
      } catch (err) {
        resultDataError = 'Failed to fetch result data from IPFS.';
        console.error('IPFS fetch error:', err);
      }
    }

    res.json({
      testId: test._id,
      testType: test.testType,
      status: test.status,
      orderedBy: test.orderedBy,
      timestamp: test.timestamp,
      resultCid: test.resultCid,
      testMetadata: test,
      resultData,
      resultDataError
    });
  } catch (err) {
    console.error('Fetch single test error:', err);
    res.status(500).json({ error: 'Failed to fetch test' });
  }
});

// Update the test results endpoint with sanitization
app.get('/api/patients/:id/tests/:testId/results',
  verifyToken,
  requireAnyRole('DOCTOR', 'ADMIN'),
  async (req, res) => {
    try {
      const { id, testId } = req.params;
      const patient = await Patient.findOne({ address: id });
      
      if (!patient) {
        return res.status(404).json({ error: 'Patient not found' });
      }

      const test = patient.tests.id(testId);
      if (!test) {
        return res.status(404).json({ error: 'Test not found' });
      }

      if (!test.resultCid) {
        return res.status(404).json({ error: 'Test results not available' });
      }

      // Fetch encrypted data from IPFS
      const pinata = new pinataSDK(process.env.PINATA_API_KEY, process.env.PINATA_API_SECRET);
      const result = await pinata.getJSONFromIPFS(test.resultCid);
      
      // Decrypt the data
      const decryptedData = await decryptData(result, test._id, id);

      res.json({
        success: true,
        testType: test.testType,
        purpose: test.purpose,
        orderedBy: test.orderedBy,
        status: test.status,
        timestamp: test.timestamp,
        results: decryptedData
      });
    } catch (error) {
      console.error('Error fetching test results:', error);
      res.status(500).json({ error: 'Failed to fetch test results' });
    }
  }
);

// POST /api/patients/:id/tests (for vaccines)
app.post('/api/patients/:id/tests',
  verifyToken,
  requireAnyRole('RECEPTIONIST'),
  async (req, res) => {
    try {
      const address = req.params.id.toLowerCase();
      const orderedBy = req.user.address;
      let tests = [];
      if (Array.isArray(req.body.tests)) {
        tests = req.body.tests.map(t => {
          let testType = '';
          if (t.category === 'test') testType = t.type;
          else if (t.category === 'vaccine') testType = t.type;
          return {
            testType,
            purpose: t.purpose || '',
            orderedBy,
            status: t.status || 'ordered',
            resultCid: undefined
          };
        });
      } else if (req.body.testType) {
        // Immutability: Prevent duplicate completed vaccine of same type
        if (req.body.status === 'completed' && req.body.testType.toLowerCase().includes('vaccine')) {
          const patient = await Patient.findOne({ address });
          if (patient && (patient.tests || []).find(t => t.testType === req.body.testType && t.status === 'completed')) {
            return res.status(400).json({ error: 'This vaccine has already been administered and cannot be repeated.' });
          }
        }
        tests = [{
          testType: req.body.testType,
          purpose: req.body.purpose || '',
          orderedBy,
          status: req.body.status || 'ordered',
          resultCid: undefined
        }];
      } else {
        return res.status(400).json({ error: 'No test(s) provided' });
      }
      const patient = await Patient.findOneAndUpdate(
        { address },
        { $push: { tests: { $each: tests } } },
        { new: true }
      );
      if (!patient) return res.status(404).json({ error: 'Patient not found' });
      res.json({ success: true, created: tests, tests: patient.tests });
    } catch (err) {
      res.status(500).json({ error: 'Failed to order test(s)' });
    }
  }
);

// Doctor/ADMIN: Get patient full details (demographics, diagnosis, tests, vitals)
app.get('/api/patients/:id',
  verifyToken,
  allowSelfOrRoles('RECEPTIONIST', 'NURSE', 'DOCTOR', 'ADMIN'),
  async (req, res) => {
    try {
      const address = req.params.id.toLowerCase();
      const patient = await Patient.findOne({ address });
      if (!patient) {
        return res.status(404).json({ error: 'Patient not found' });
      }
      // Role-specific data filtering
      if (await contract.isRole(req.user.address, ROLES.RECEPTIONIST)) { 
        // Receptionist and Nurse: only demographics
        return res.json({ 
          address: patient.address,
          demographics: decryptDemographics(patient.demographics, process.env.MASTER_KEY) });
      } else if (await contract.isRole(req.user.address, ROLES.NURSE)) {
        // Nurse: only vitals
        return res.json({ 
          address: patient.address,
          demographics: decryptDemographics(patient.demographics, process.env.MASTER_KEY),
          vitals: patient.vitals || [] });
      }
      // Doctor and Admin get full access
      res.json({
        address: patient.address,
        demographics: decryptDemographics(patient.demographics, process.env.MASTER_KEY),
        diagnosis: patient.diagnosis || [],
        tests: patient.tests || [],
        vitals: patient.vitals || []
      });
    } catch (err) {
      logger.error('Patient data access error:', err);
      res.status(500).json({ error: 'Failed to fetch patient' });
    }
  }
);

// GET /api/patients/:id/certificates – List all certificates for a patient
app.get('/api/patients/:id/certificates', verifyToken, allowSelfOrRoles('DOCTOR', 'ADMIN'), async (req, res) => {
  try {
    const patient = req.params.id.toLowerCase();
    const certs = await HealthCertificate.find({ patient });
    await AuditLog.create({
      type: 'ACTION',
      action: 'view_certificates',
      role: req.user.address === patient ? 'patient' : 'doctor_or_admin',
      address: req.user.address,
      target: patient,
      timestamp: new Date(),
      message: `${req.user.address} viewed certificates for ${patient}`
    });
    res.json({ certificates: certs });
  } catch (err) {
    logger.error('Patient certificate list error:', err);
    res.status(500).json({ error: 'Failed to fetch certificates' });
  }
});

// DELETE /api/certificates/:id – Delete certificate (admin only)
app.delete('/api/certificates/:id', verifyToken, requireRole('ADMIN'), async (req, res) => {
  try {
    const cert = await HealthCertificate.findByIdAndDelete(req.params.id);
    if (!cert) return res.status(404).json({ error: 'Certificate not found' });
    await AuditLog.create({
      type: 'ACTION',
      action: 'delete_certificate',
      role: 'admin',
      address: req.user.address,
      target: req.params.id,
      timestamp: new Date(),
      message: `Admin deleted certificate ${req.params.id}`
    });
    res.json({ success: true });
  } catch (err) {
    logger.error('Certificate delete error:', err);
    res.status(500).json({ error: 'Failed to delete certificate' });
  }
});

// GET /api/patients - List all patients (doctor/admin only)
app.get('/api/patients',
  verifyToken,
  requireAnyRole('DOCTOR', 'ADMIN'),
  async (req, res) => {
    try {
      const patients = await Patient.find({});
      res.json(patients);
    } catch (err) {
      logger.error('Fetch all patients error:', err);
      res.status(500).json({ error: 'Failed to fetch patients' });
    }
  }
);

// Add secure encryption functions
async function encryptData(data, testId, patientAddress) {
  // Convert data to string if it's an object
  const dataString = typeof data === 'object' ? JSON.stringify(data) : data;
  
  // Generate a random data encryption key (DEK)
  const dek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  
  // Encrypt the data with DEK
  const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
  let encrypted = cipher.update(dataString, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const authTag = cipher.getAuthTag();

  // Encrypt the DEK with master key (KEK)
  const masterKey = Buffer.from(process.env.MASTER_KEY, 'hex');
  const kekIv = crypto.randomBytes(16);
  const kekCipher = crypto.createCipheriv('aes-256-cbc', masterKey, kekIv);
  let encryptedDek = kekCipher.update(dek);
  encryptedDek = Buffer.concat([encryptedDek, kekCipher.final()]);

  // Store the encrypted DEK in MongoDB
  await EncryptionKey.findOneAndUpdate(
    { testId, patientAddress },
    {
      encryptedDek: encryptedDek.toString('base64'),
      iv: kekIv.toString('base64'),
      updatedAt: new Date()
    },
    { upsert: true, new: true }
  );

  // Return only the encrypted data and metadata (no keys)
  return {
    encrypted: encrypted,
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64')
  };
}

async function decryptData(encryptedData, testId, patientAddress) {
  try {
    // Get the encrypted DEK from MongoDB
    const keyRecord = await EncryptionKey.findOne({ testId, patientAddress });
    if (!keyRecord) {
      throw new Error('Encryption key not found');
    }

    // Decrypt the DEK using master key
    const masterKey = Buffer.from(process.env.MASTER_KEY, 'hex');
    const kekIv = Buffer.from(keyRecord.iv, 'base64');
    const encryptedDek = Buffer.from(keyRecord.encryptedDek, 'base64');
    
    const kekDecipher = crypto.createDecipheriv('aes-256-cbc', masterKey, kekIv);
    let dek = kekDecipher.update(encryptedDek);
    dek = Buffer.concat([dek, kekDecipher.final()]);

    // Decrypt the data using DEK
    const iv = Buffer.from(encryptedData.iv, 'base64');
    const authTag = Buffer.from(encryptedData.authTag, 'base64');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', dek, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encryptedData.encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    // Try to parse as JSON if possible
    try {
      return JSON.parse(decrypted);
    } catch {
      return decrypted;
    }
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Failed to decrypt data');
  }
}

// Update test results endpoint with sanitization
app.patch('/api/patients/:id/tests/:testId',
  verifyToken,
  requireAnyRole('NURSE', 'DOCTOR', 'ADMIN'),
  async (req, res) => {
    try {
      const { id, testId } = req.params;
      const { resultData } = req.body;

      // Find patient and test
      const patient = await Patient.findOne({ address: id });
      if (!patient) {
        return res.status(404).json({ error: 'Patient not found' });
      }

      const test = patient.tests.id(testId);
      if (!test) {
        return res.status(404).json({ error: 'Test not found' });
      }

      // Immutability: Prevent updating if already completed
      if (test.status === 'completed') {
        return res.status(400).json({ error: 'Test result already submitted and cannot be updated.' });
      }

      // Encrypt result data and store key in MongoDB
      const encryptedData = await encryptData(resultData, test._id, id);

      // Upload to IPFS using Pinata
      const options = {
        pinataMetadata: {
          name: `Test Result - ${test.testType} - ${new Date().toISOString()}`,
        },
      };

      const pinata = new pinataSDK(process.env.PINATA_API_KEY, process.env.PINATA_API_SECRET);
      const result = await pinata.pinJSONToIPFS(encryptedData, options);
      const resultCid = result.IpfsHash;

      // Update test with result
      test.resultCid = resultCid;
      test.status = 'completed';
      await patient.save();

      res.json({ 
        success: true, 
        message: 'Test results updated successfully',
        resultCid 
      });
    } catch (error) {
      console.error('error: Update test error:', error);
      res.status(500).json({ error: 'Failed to update test' });
    }
  }
);

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// Port configuration
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});

// --- Secure Middleware: Allow Self or Roles ---
function allowSelfOrRoles(...roles) {
  return async (req, res, next) => {
    // Use the correct param name!
    const address = typeof req.params.id === 'string'
      ? req.params.id.toLowerCase()
      : typeof req.params.address === 'string'
      ? req.params.address.toLowerCase()
      : '';
    if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
      return res.status(400).json({ error: 'Invalid address format' });
    }
    if (
      req.user &&
      req.user.address &&
      req.user.address.toLowerCase() === address
    ) {
      return next();
    }
    return requireAnyRole(...roles)(req, res, next);
  };
}

// POST /api/issue-certificate (combined diagnosis + cert metadata)
app.post('/api/issue-certificate', verifyToken, async (req, res) => {
  try {
    console.log('POST /api/issue-certificate body:', req.body);
    let { patient, issuedBy, certType, attestation, testId, ipfsCid } = req.body;
    const { ethers } = require('ethers');
    // If ipfsCid is not provided, generate and upload the certificate file to IPFS
    if (!ipfsCid) {
      // Build the certificate file (JSON)
      const certFile = {
        patient: patient.toLowerCase(),
        issuedBy: issuedBy.toLowerCase(),
        certType,
        attestation,
        issuedAt: new Date().toISOString(),
      };
      // Encrypt the certificate file using AES-256-GCM (like test results)
      // Generate a random data encryption key (DEK)
      const dek = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
      let encrypted = cipher.update(JSON.stringify(certFile), 'utf8', 'base64');
      encrypted += cipher.final('base64');
      const authTag = cipher.getAuthTag();
      // Encrypt the DEK with master key (KEK)
      const masterKey = Buffer.from(process.env.MASTER_KEY, 'hex');
      const kekIv = crypto.randomBytes(16);
      const kekCipher = crypto.createCipheriv('aes-256-cbc', masterKey, kekIv);
      let encryptedDek = kekCipher.update(dek);
      encryptedDek = Buffer.concat([encryptedDek, kekCipher.final()]);
      // Store the encrypted DEK in MongoDB (type: 'certificate')
      await EncryptionKey.findOneAndUpdate(
        { testId: null, patientAddress: patient.toLowerCase(), certType: certType },
        {
          encryptedDek: encryptedDek.toString('base64'),
          iv: kekIv.toString('base64'),
          updatedAt: new Date(),
          type: 'certificate',
          certType: certType
        },
        { upsert: true, new: true }
      );
      // Prepare encrypted object for IPFS
      const encryptedCert = {
        encrypted,
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64')
      };
      // Upload to IPFS (Pinata)
      const pinata = new pinataSDK(process.env.PINATA_API_KEY, process.env.PINATA_API_SECRET);
      const options = { pinataMetadata: { name: `Certificate - ${new Date().toISOString()}` } };
      const result = await pinata.pinJSONToIPFS(encryptedCert, options);
      ipfsCid = result.IpfsHash;
    }
    const certHash = ethers.keccak256(ethers.toUtf8Bytes(ipfsCid));
    // Save certificate
    const cert = await HealthCertificate.create({
      patient: patient.toLowerCase(),
      issuedBy: issuedBy.toLowerCase(),
      certType,
      attestation,
      ipfsCid,
      certHash,
      issuedAt: new Date()
    });
    // Update the test to mark as certified and status as 'issued'
    if (testId) {
      await Patient.updateOne(
        { address: patient.toLowerCase(), 'tests._id': testId },
        { $set: { 'tests.$.certified': true, 'tests.$.status': 'issued' } }
      );
    }
    // Push attestation object to Patient.diagnosis array (for history)
    await Patient.findOneAndUpdate(
      { address: patient.toLowerCase() },
      {
        $push: {
          diagnosis: {
            attestation,
            timestamp: new Date(),
            doctorAddress: issuedBy
          }
        }
      }
    );
    res.json({ certHash, ipfsCid });
  } catch (err) {
    console.error('Error in /api/issue-certificate:', err);
    res.status(500).json({ error: 'Failed to save certificate' });
  }
});

// PATCH endpoint to add signature after certHash is returned
app.patch('/api/issue-certificate/:certHash/signature', verifyToken, async (req, res) => {
  try {
    const { certHash } = req.params;
    const { signature } = req.body;
    if (!signature) return res.status(400).json({ error: 'Signature is required' });
    const cert = await HealthCertificate.findOneAndUpdate(
      { certHash },
      { signature },
      { new: true }
    );
    if (!cert) return res.status(404).json({ error: 'Certificate not found' });
    res.json({ success: true, cert });
  } catch (err) {
    console.error('Error in PATCH /api/issue-certificate/:certHash/signature:', err);
    res.status(500).json({ error: 'Failed to update signature' });
  }
});

app.post('/api/verify-certificate', async (req, res) => {
  try {
    const { patientAddress, certHash } = req.body;
    if (!patientAddress || !certHash) {
      return res.status(400).json({ error: 'patientAddress and certHash are required' });
    }

    // 1. Get all cert hashes for this patient from the blockchain
    const onChainCerts = await contract.getCertificates(patientAddress);
    const foundOnChain = onChainCerts.map(h => h.toLowerCase()).includes(certHash.toLowerCase());
    console.log('On-chain certs:', onChainCerts);
    console.log('Found on chain:', foundOnChain);

    // 2. Fetch the certificate from MongoDB
    const cert = await HealthCertificate.findOne({ patient: patientAddress, certHash });
    if (!cert) {
      console.log('Not found in DB');
      return res.json({ isValid: false, reason: 'Not found in DB' });
    }

    // 3. Recompute the hash of the CID
    const computedHash = ethers.keccak256(ethers.toUtf8Bytes(cert.ipfsCid));
    const hashMatch = computedHash === certHash;
    console.log('MongoDB CID:', cert.ipfsCid);
    console.log('Computed hash:', computedHash);
    console.log('Hash match:', hashMatch);

    // 4. Check IPFS with fallback logic
    let ipfsOk = false;
    const gateways = [
      'https://gateway.pinata.cloud/ipfs/',
      'https://cloudflare-ipfs.com/ipfs/',
      'https://ipfs.io/ipfs/'
    ];
    for (const gw of gateways) {
    try {
        const ipfsRes = await axios.get(gw + cert.ipfsCid, { responseType: 'text' });
        if (ipfsRes.data) {
          ipfsOk = true;
          break;
        }
      } catch (e) {
        // continue to next gateway
      }
    }
    console.log('IPFS OK:', ipfsOk);

    res.json({
      isValid: foundOnChain && hashMatch && ipfsOk,
      foundOnChain,
      hashMatch,
      ipfsOk,
      certHash,
      cid: cert.ipfsCid
    });
  } catch (err) {
    console.error('Error in /api/verify-certificate:', err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// PATCH /api/certificates/:certHash/tx - Update transaction hash for a certificate
app.patch('/api/certificates/:certHash/tx', verifyToken, async (req, res) => {
  try {
    const { certHash } = req.params;
    const { transactionHash } = req.body;
    const cert = await HealthCertificate.findOneAndUpdate(
      { certHash },
      { transactionHash },
      { new: true }
    );
    if (!cert) return res.status(404).json({ error: 'Certificate not found' });
    res.json({ success: true, cert });
  } catch (err) {
    console.error('Error updating certificate transaction hash:', err);
    res.status(500).json({ error: 'Failed to update transaction hash' });
  }
});

// --- GET /api/audit-logs (Admin only, paginated, filterable) ---
app.get('/api/audit-logs', verifyToken, requireRole('ADMIN'), async (req, res) => {
  try {
    const {
      type,
      action,
      role,
      address,
      start,
      end,
      page = 1,
      pageSize = 20
    } = req.query;

    // Build filter object
    const filter = {};
    if (type) filter.type = type;
    if (action) filter.action = action;
    if (role) filter.role = role;
    if (address) filter.address = address;
    if (start || end) {
      filter.timestamp = {};
      if (start) filter.timestamp.$gte = new Date(start);
      if (end) filter.timestamp.$lte = new Date(end);
    }

    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(pageSize);
    const limit = parseInt(pageSize);

    // Query logs
    const logs = await AuditLog.find(filter)
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limit)
      .lean();
    const total = await AuditLog.countDocuments(filter);

    // Optionally, log this access
    await AuditLog.create({
      type: 'AUDIT_ACCESS',
      action: 'view_audit_logs',
      role: 'admin',
      address: req.user.address,
      timestamp: new Date(),
      message: `Admin fetched audit logs`
    });

    res.json({ logs, total, page: parseInt(page), pageSize: limit });
  } catch (err) {
    logger.error('Audit log fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

// GET /api/patients/:id/certificates/:certHash/ - Fetch and decrypt a certificate for a patient
app.get('/api/patients/:id/certificates/:certHash/', verifyToken, allowSelfOrRoles('DOCTOR', 'ADMIN'), async (req, res) => {
  res.set('Cache-Control', 'no-store');
  console.log('CERT ENDPOINT HIT', req.params.id, req.params.certHash, new Date());
  try {
    const patientAddress = req.params.id.toLowerCase();
    const certHash = req.params.certHash;
    // Find the certificate
    
    const cert = await HealthCertificate.findOne({ patient: patientAddress, certHash });
    if (!cert) return res.status(404).json({ error: 'Certificate not found' });
    if (!cert.ipfsCid) return res.status(404).json({ error: 'Certificate IPFS CID missing' });
    // Fetch encrypted certificate from IPFS
    const response = await axios.get(`https://gateway.pinata.cloud/ipfs/${cert.ipfsCid}`);
    const encryptedCert = response.data;
    // Find the encrypted DEK in MongoDB
    const keyRecord = await EncryptionKey.findOne({ testId: null, patientAddress, certType: cert.certType, type: 'certificate' });
    if (!keyRecord) return res.status(404).json({ error: 'Encryption key not found' });
    // Decrypt the DEK using master key
    const masterKey = Buffer.from(process.env.MASTER_KEY, 'hex');
    const kekIv = Buffer.from(keyRecord.iv, 'base64');
    const encryptedDek = Buffer.from(keyRecord.encryptedDek, 'base64');
    const kekDecipher = crypto.createDecipheriv('aes-256-cbc', masterKey, kekIv);
    let dek = kekDecipher.update(encryptedDek);
    dek = Buffer.concat([dek, kekDecipher.final()]);
    // Decrypt the certificate data using DEK
    const iv = Buffer.from(encryptedCert.iv, 'base64');
    const authTag = Buffer.from(encryptedCert.authTag, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', dek, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encryptedCert.encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    let certData;
    try {
      certData = JSON.parse(decrypted);
    } catch {
      certData = decrypted;
    }
    res.json({
      success: true,
      cert: certData,
      certHash,
      ipfsCid: cert.ipfsCid,
      certType: cert.certType,
      issuedAt: cert.issuedAt,
      issuedBy: cert.issuedBy
    });
  } catch (err) {
    console.error('Error fetching/decrypting certificate:', err);
    res.status(500).json({ error: 'Failed to fetch or decrypt certificate' });
  }
});

// Input sanitization and validation functions
function sanitizeAddress(address) {
  if (!address || typeof address !== 'string') return null;
  const sanitized = address.toLowerCase().trim();
  return ethers.isAddress(sanitized) ? sanitized : null;
}

function sanitizeRole(role) {
  if (!role || typeof role !== 'string') return null;
  const sanitized = role.toUpperCase().trim();
  return ROLES[sanitized] ? sanitized : null;
}

function sanitizeString(input) {
  if (!input || typeof input !== 'string') return null;
  return input.trim();
}

function sanitizeObjectId(id) {
  if (!id || typeof id !== 'string') return null;
  return mongoose.Types.ObjectId.isValid(id) ? id : null;
}