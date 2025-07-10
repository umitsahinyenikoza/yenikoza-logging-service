const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const moment = require('moment');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const PDFDocument = require('pdfkit');
const ExcelJS = require('exceljs');

// 🆕 Environment kontrolü - Production'da console.log'ları kapat
const isDevelopment = process.env.NODE_ENV !== 'production';
const debugLog = (...args) => {
  if (isDevelopment) {
    console.log(...args);
  }
};

const app = express();

debugLog('ÇALIŞAN DOSYA:', __filename);

// Middleware
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:5174', 
    'http://localhost:5175', 
    'http://localhost:5176', 
    'http://localhost:5177', 
    'http://localhost:3000',
    'https://yenikoza-dashboard-k23r.vercel.app'
  ],
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));

// Logging middleware
app.use((req, res, next) => {
  debugLog(`${moment().format('YYYY-MM-DD HH:mm:ss')} - ${req.method} ${req.path}`);
  next();
});

// Constants
const LOGS_DIR = path.join(__dirname, 'logs');
const USERS_FILE = path.join(__dirname, 'users.json');
const JWT_SECRET = process.env.JWT_SECRET || 'yenikoza-dashboard-secret-2025';

const ensureLogsDir = async () => {
  try {
    await fs.access(LOGS_DIR);
  } catch {
    await fs.mkdir(LOGS_DIR, { recursive: true });
    debugLog(`📁 Created logs directory: ${LOGS_DIR}`);
  }
};

// Hiyerarşik log yapısı için yardımcı fonksiyonlar
const ensureHierarchicalLogsDir = async (date) => {
  try {
    const year = date.getFullYear().toString();
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const day = date.getDate().toString().padStart(2, '0');
    
    const yearDir = path.join(LOGS_DIR, year);
    const monthDir = path.join(yearDir, month);
    const dayDir = path.join(monthDir, day);
    
    // Yıl, ay ve gün klasörlerini oluştur
    await fs.mkdir(yearDir, { recursive: true });
    await fs.mkdir(monthDir, { recursive: true });
    await fs.mkdir(dayDir, { recursive: true });
    
    return dayDir;
  } catch (error) {
    debugLog('❌ Error creating hierarchical logs directory:', error);
    throw error;
  }
};

// Hiyerarşik yapıda log dosyası oluştur
const createHierarchicalLogFile = async (date, deviceId) => {
  const dayDir = await ensureHierarchicalLogsDir(date);
  const filename = `${deviceId || 'unknown'}.json`;
  const filepath = path.join(dayDir, filename);
  
  return filepath;
};

// Hiyerarşik yapıdan logları oku
const readLogsFromHierarchicalStructure = async (startDate, endDate) => {
  const logs = [];
  const start = new Date(startDate);
  const end = new Date(endDate);
  
  debugLog(`🔍 readLogsFromHierarchicalStructure: Reading from ${start.toISOString().split('T')[0]} to ${end.toISOString().split('T')[0]}`);
  
  // Tarih aralığındaki tüm günleri döngüye al
  const currentDate = new Date(start);
  while (currentDate <= end) {
    try {
      const year = currentDate.getFullYear().toString();
      const month = (currentDate.getMonth() + 1).toString().padStart(2, '0');
      const day = currentDate.getDate().toString().padStart(2, '0');
      
      const dayDir = path.join(LOGS_DIR, year, month, day);
      
      debugLog(`🔍 Checking directory: ${dayDir}`);
      
      // Gün klasörü var mı kontrol et
      try {
        await fs.access(dayDir);
        debugLog(`✅ Directory exists: ${dayDir}`);
      } catch {
        // Klasör yoksa bu gün için log yok
        debugLog(`❌ Directory not found: ${dayDir}`);
        currentDate.setDate(currentDate.getDate() + 1);
        continue;
      }
      
      // Gün klasöründeki tüm dosyaları oku
      const files = await fs.readdir(dayDir);
      debugLog(`📁 Files in ${dayDir}:`, files);
      
      for (const file of files) {
        if (file.endsWith('.json')) {
          try {
            const data = await fs.readFile(path.join(dayDir, file), 'utf8');
            const dayLogs = JSON.parse(data);
            debugLog(`📄 Read ${dayLogs.length} logs from ${file}`);
            logs.push(...dayLogs);
          } catch (error) {
            debugLog('❌ Error reading log file:', error);
          }
        }
      }
    } catch (error) {
      debugLog('❌ Error processing date:', error);
    }
    
    // Sonraki güne geç
    currentDate.setDate(currentDate.getDate() + 1);
  }
  
  debugLog(`🔍 readLogsFromHierarchicalStructure: Found ${logs.length} logs`);
  
  // Debug: Log seviyelerini kontrol et
  const levelCounts = {};
  logs.forEach(log => {
    levelCounts[log.level] = (levelCounts[log.level] || 0) + 1;
  });
  debugLog(`🔍 Log levels in hierarchical structure:`, levelCounts);
  
  return logs;
};

// Eski log dosyalarını yeni hiyerarşik yapıya taşı
const migrateOldLogsToHierarchicalStructure = async () => {
  try {
    debugLog('🔄 Starting migration of old logs to hierarchical structure...');
    
    const files = await fs.readdir(LOGS_DIR);
    let migratedCount = 0;
    
    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      
      // Eski format: YYYY-MM-DD-device_id.json
      const dateMatch = file.match(/^(\d{4})-(\d{2})-(\d{2})-(.+?)\.json$/);
      if (!dateMatch) continue;
      
      const [, year, month, day, deviceId] = dateMatch;
      const oldFilePath = path.join(LOGS_DIR, file);
      
      try {
        // Eski dosyayı oku
        const data = await fs.readFile(oldFilePath, 'utf8');
        const logs = JSON.parse(data);
        
        // Yeni hiyerarşik yapıda dosya oluştur
        const targetDate = new Date(`${year}-${month}-${day}`);
        const newFilePath = await createHierarchicalLogFile(targetDate, deviceId);
        
        // Logları yeni dosyaya yaz
        await fs.writeFile(newFilePath, JSON.stringify(logs, null, 2));
        
        // Eski dosyayı sil
        await fs.unlink(oldFilePath);
        
        debugLog(`✅ Migrated: ${file} -> ${path.relative(LOGS_DIR, newFilePath)}`);
        migratedCount++;
        
      } catch (error) {
        debugLog('❌ Error migrating:', error);
      }
    }
    
    debugLog(`🎉 Migration completed! ${migratedCount} files migrated.`);
    return migratedCount;
    
  } catch (error) {
    debugLog('❌ Migration error:', error);
    throw error;
  }
};

// Load users from JSON file
const loadUsers = async () => {
  try {
    const data = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    debugLog('❌ Failed to load users:', error);
    return [];
  }
};

// Save users to JSON file
const saveUsers = async (users) => {
  try {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
    return true;
  } catch (error) {
    debugLog('❌ Failed to save users:', error);
    return false;
  }
};

// Store name mapping
const storeNames = {
  'E014': 'Ender Park Adana',
  'Y013': 'Yeni Koza Adana',
  'Y261': 'Ender Eskişehir',
  'Y332': 'Yeni Koza Mersin',
  'Y342': 'Ender Bakırköy',
  'Y421': 'Yeni Koza Konya'
};

// Store address mapping
const storeAddresses = {
  'E014': 'Adana Kurtuluş Mah. Turhan Cemal Beriker Blv. No:701/A',
  'Y013': 'Adana Tepebağ Mah. 1453 Sokak No:4/A',
  'Y261': 'Eskişehir Merkez İlçe, Akarbaşı Mah.',
  'Y332': 'Mersin Yenişehir İlçe, Çiftlikköy Mah.',
  'Y342': 'İstanbul Bakırköy İlçe, Ataköy Mah.',
  'Y421': 'Konya Selçuklu İlçe, Buhara Mah.'
};

// Helper function to get store address
const getStoreAddress = (storeCode) => {
  return storeAddresses[storeCode] || `${storeNames[storeCode] || storeCode} Mağaza Adresi`;
};

// ====== API ENDPOINTS ======

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'YeniKoza Logging Service'
  });
});

// ====== AUTHENTICATION ENDPOINTS ======

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        error: 'Username and password are required' 
      });
    }
    
    // Load users from file
    const users = await loadUsers();
    
    // Find user
    const user = users.find(u => u.username === username && u.active);
    if (!user) {
      debugLog(`❌ Login failed - User not found: ${username}`);
      return res.status(401).json({ 
        error: 'Geçersiz kullanıcı adı veya şifre' 
      });
    }
    
    // Check password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      debugLog(`❌ Login failed - Invalid password for user: ${username}`);
      return res.status(401).json({ 
        error: 'Geçersiz kullanıcı adı veya şifre' 
      });
    }
    
    // Update last login time
    user.lastLogin = new Date().toISOString();
    await saveUsers(users);
    
    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user.id, 
        username: user.username, 
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // Remove sensitive data
    const { passwordHash, ...userResponse } = user;
    
    debugLog(`✅ Login successful for user: ${username} (${user.role})`);
    
    res.json({
      success: true,
      user: userResponse,
      token,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    });
    
  } catch (error) {
    debugLog('❌ Login error:', error);
    res.status(500).json({ 
      error: 'Login failed',
      message: error.message 
    });
  }
});

// Token verification middleware
const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Load user to check if still active
    const users = await loadUsers();
    const user = users.find(u => u.id === decoded.userId && u.active);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found or inactive' });
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Get current user info
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const users = await loadUsers();
    const user = users.find(u => u.id === req.user.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const { passwordHash, ...userResponse } = user;
    res.json(userResponse);
    
  } catch (error) {
    res.status(500).json({ error: 'Failed to get user info' });
  }
});

// Logout endpoint (optional - mainly for client-side cleanup)
app.post('/api/auth/logout', verifyToken, (req, res) => {
  debugLog(`🚪 User ${req.user.username} logged out`);
  res.json({ success: true, message: 'Logged out successfully' });
});

// Tablet'lerden log alma endpoint'i
app.post('/api/tablet-logs', async (req, res) => {
  try {
    const { logs, device_id, timestamp } = req.body;
    
    if (!logs || !Array.isArray(logs)) {
      return res.status(400).json({ error: 'Invalid logs format' });
    }

    await ensureLogsDir();
    
    // Her logu kendi timestamp'ine göre ilgili klasöre kaydet
    const logsByFile = {};
    for (const log of logs) {
      const logTime = log.timestamp ? new Date(log.timestamp) : new Date();
      debugLog(`[DEBUG] log.timestamp:`, log.timestamp);
      debugLog(`[DEBUG] logTime:`, logTime.toISOString());
      debugLog(`[DEBUG] logTime.getFullYear():`, logTime.getFullYear());
      debugLog(`[DEBUG] logTime.getMonth():`, logTime.getMonth());
      debugLog(`[DEBUG] logTime.getDate():`, logTime.getDate());
      
      const filePath = await createHierarchicalLogFile(logTime, log.device_id || device_id);
      debugLog(`[DEBUG] filePath:`, filePath);
      
      if (!logsByFile[filePath]) logsByFile[filePath] = [];
      logsByFile[filePath].push({
        ...log,
        received_at: new Date().toISOString(),
        device_id: log.device_id || device_id || 'unknown'
      });
    }

    let totalSaved = 0;
    for (const [filePath, logsArr] of Object.entries(logsByFile)) {
      let existingLogs = [];
      try {
        const data = await fs.readFile(filePath, 'utf8');
        existingLogs = JSON.parse(data);
      } catch (error) {
        // Dosya yoksa boş array ile başla
        debugLog(`📝 Creating new hierarchical log file: ${path.relative(LOGS_DIR, filePath)}`);
      }
      existingLogs.push(...logsArr);
      await fs.writeFile(filePath, JSON.stringify(existingLogs, null, 2));
      totalSaved += logsArr.length;
    }

    res.json({ 
      success: true, 
      count: totalSaved,
      files: Object.keys(logsByFile).map(f => path.relative(LOGS_DIR, f)),
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    debugLog('❌ Log save error:', error);
    res.status(500).json({ 
      error: 'Failed to save logs',
      message: error.message 
    });
  }
});

// Dashboard için veri endpoint'i
app.get('/api/dashboard/data', async (req, res) => {
  try {
    const scope = (req.query.scope || 'daily').toLowerCase();
    const dashboardData = await getAllDashboardData(scope);
    res.json(dashboardData);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get dashboard data', message: error.message });
  }
});

// Dashboard overview
app.get('/api/dashboard/overview', async (req, res) => {
  try {
    const scope = (req.query.scope || 'daily').toLowerCase();
    debugLog('🔍 Overview endpoint called with scope:', scope);
    const data = await getAllDashboardData(scope);
    debugLog('🔍 Overview data:', data.overview);
    debugLog('🔍 Overview totalLogs:', data.overview.totalLogs);
    debugLog('�� Overview todayLogs:', data.overview.todayLogs);
    const activeStoresCount = data.stores.filter(store => store.status === 'active' && store.storeCode && store.storeCode !== 'UNKNOWN').length;
    const overviewResponse = {
      overview: data.overview, // ✅ Tüm overview verilerini dahil et
      stores: data.stores, // ✅ Store verilerini dahil et
      trends: data.trends, // ✅ Trend verilerini dahil et
      metrics: {
        totalUsers: data.overview.activeTablets || 0,
        totalOrders: data.overview.totalLogs || 0, // ✅ Scope'a göre toplam log sayısı
        totalRevenue: data.overview.successCount || 0,
        systemHealth: Math.round(data.overview.successRate) || 0,
        activeStores: activeStoresCount,
        pendingApprovals: data.overview.errorCount || 0
      }
    };
    debugLog('🔍 Overview response:', overviewResponse);
    res.json(overviewResponse);
  } catch (error) {
    debugLog('❌ Overview error:', error);
    res.status(500).json({ error: 'Failed to get overview', details: error.message });
  }
});

// Dashboard alerts
app.get('/api/dashboard/alerts', async (req, res) => {
  try {
    const scope = (req.query.scope || 'daily').toLowerCase();
    const data = await getAllDashboardData(scope);
    const alerts = data.recentErrors.slice(0, 5).map((error, index) => ({
      id: index + 1,
      type: 'error',
      title: error.store_code === 'UNKNOWN' ? '⚠️ Login Öncesi Hata' : `${error.storeName || error.store_code}`,
      message: error.message || 'Bilinmeyen hata',
      timestamp: error.timestamp,
      isRead: readAlertIds.has(index + 1), // RAM'deki okundu dizisine bak
      isPreLogin: error.store_code === 'UNKNOWN'
    }));
    res.json(alerts);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get alerts' });
  }
});

// 🆕 Okundu alert ID'lerini RAM'de tut
const readAlertIds = new Set();

// 🆕 PATCH /api/dashboard/alerts/:id/read
app.patch('/api/dashboard/alerts/:id/read', (req, res) => {
  const alertId = parseInt(req.params.id, 10);
  if (isNaN(alertId)) {
    return res.status(400).json({ error: 'Geçersiz alert ID' });
  }
  readAlertIds.add(alertId);
  res.json({ success: true, id: alertId });
});

// Dashboard activities
app.get('/api/dashboard/activities', async (req, res) => {
  try {
    const scope = (req.query.scope || 'daily').toLowerCase();
    const data = await getAllDashboardData(scope);
    const activities = data.recentSuccess.slice(0, 10).map((log, index) => ({
      id: index + 1,
      title: `${log.storeName || log.store_code} - ${log.category}`,
      description: log.message,
      details: `Store: ${log.store_code}, Plasiyer: ${log.plasiyer_name || 'N/A'}`,
      timestamp: log.timestamp,
      // ✅ DÜZELTME: Plasiyer ve müşteri isimlerini ayrı alanlar olarak ekle
      plasiyerName: log.plasiyer_name || 'N/A',
      customerName: log.data?.customerName || log.data?.fullName || 'N/A',
      storeCode: log.store_code,
      storeName: log.storeName || log.store_code
    }));
    res.json(activities);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get activities' });
  }
});

// Dashboard store-status
app.get('/api/dashboard/store-status', async (req, res) => {
  try {
    const scope = (req.query.scope || 'daily').toLowerCase();
    const data = await getAllDashboardData(scope);
    let storeStatus = data.stores;
    if (storeStatus && storeStatus.length > 0) {
      storeStatus = storeStatus.filter(store => store.storeCode && store.storeCode !== 'UNKNOWN' && store.storeName && store.storeName !== 'UNKNOWN' && store.storeName !== 'Store UNKNOWN');
    }
    if (!storeStatus || storeStatus.length === 0) {
      storeStatus = [];
    }
    const formattedStoreStatus = storeStatus.map(store => ({
      id: store.storeCode,
      name: store.storeName,
      code: store.storeCode,
      status: store.status || 'active',
      customerCount: store.customerCount || 0,
      errorCount: store.errorCount || 0,
      lastActivity: store.lastActivity,
      location: storeNames[store.storeCode] ? 'Türkiye' : 'Bilinmiyor',
      totalTablets: store.totalTablets || 0,
      onlineTablets: store.onlineTablets || 0,
      offlineTablets: store.offlineTablets || 0,
      tabletDetails: store.tabletDetails || [],
      totalLogs: store.totalLogs || 0
    }));
    res.json(formattedStoreStatus);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get store status' });
  }
});

// Dashboard sms-logs
app.get('/api/dashboard/sms-logs', async (req, res) => {
  try {
    const scope = (req.query.scope || 'daily').toLowerCase();
    const data = await getAllDashboardData(scope);
    const allLogs = data.recentErrors.concat(data.recentSuccess || []);
    const smsLogs = allLogs.filter(log => log.category === 'SMS_APPROVAL' || log.category === 'SMS_NOTIFICATION');
    const formattedSmsLogs = smsLogs.map(log => ({
      id: log.id,
      timestamp: log.timestamp,
      level: log.level,
      category: log.category,
      message: log.message,
      data: log.data,
      storeCode: log.store_code,
      storeName: storeNames[log.store_code] || log.store_code,
      plasiyerName: log.plasiyer_name,
      deviceId: log.device_id,
      smsType: log.category === 'SMS_NOTIFICATION' ? 'ACCOUNT_NOTIFICATION' : 'VERIFICATION',
      phoneNumber: log.data?.phoneNumber || 'Unknown'
    })).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    const sentRequests = smsLogs.filter(log => log.message && (log.message.includes('SMS code request started') || log.message.includes('Send Account SMS started'))).length;
    const sentSuccesses = smsLogs.filter(log => log.message && (log.message.includes('SMS sent successfully') || log.message.includes('Customer account SMS sent successfully'))).length;
    const totalSent = sentRequests > 0 ? sentRequests : sentSuccesses;
    res.json({
      logs: formattedSmsLogs,
      total: formattedSmsLogs.length,
      stats: {
        totalSent: totalSent,
        totalSuccess: sentSuccesses,
        totalFailed: smsLogs.filter(log => log.level === 'ERROR').length,
        approvalSms: smsLogs.filter(log => log.category === 'SMS_APPROVAL').length,
        notificationSms: smsLogs.filter(log => log.category === 'SMS_NOTIFICATION').length
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get SMS logs' });
  }
});

// Stores endpoint
app.get('/api/stores', async (req, res) => {
  try {
    const scope = (req.query.scope || 'daily').toLowerCase();
    const data = await getAllDashboardData(scope);
    const storesWithAddress = data.stores.map(store => ({
      id: store.storeCode,
      name: store.storeName,
      code: store.storeCode,
      status: store.status,
      address: getStoreAddress(store.storeCode),
      totalLogs: store.totalLogs || 0,
      errorCount: store.errorCount,
      successCount: store.successCount,
      customerCount: store.customerCount,
      lastActivity: store.lastActivity
    }));
    res.json(storesWithAddress);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get stores' });
  }
});

// Stores status endpoint
app.get('/api/stores/status', async (req, res) => {
  try {
    const scope = (req.query.scope || 'daily').toLowerCase();
    const data = await getAllDashboardData(scope);
    const storeStatusData = data.stores.map(store => ({
      storeCode: store.storeCode,
      storeName: store.storeName,
      status: store.status,
      address: getStoreAddress(store.storeCode),
      customerCount: store.customerCount, // 👤 Gerçek müşteri sayısı (totalLogs değil!)
      errorCount: store.errorCount,
      lastActivity: store.lastActivity,
      isActive: store.status === 'active',
      // 🆕 Tablet durum bilgileri
      totalTablets: store.totalTablets || 0,
      onlineTablets: store.onlineTablets || 0,
      offlineTablets: store.offlineTablets || 0,
      tabletDetails: store.tabletDetails || [],
      // 🔥 EKSIK OLAN FIELD!
      totalLogs: store.totalLogs || 0
    }));
    
    res.json(storeStatusData);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get stores status' });
  }
});

app.get('/api/stores/summary', async (req, res) => {
  try {
    const data = await getAllDashboardData();
    res.json({ total: data.stores.length, active: data.stores.length });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get stores summary' });
  }
});

app.get('/api/sms/analytics', async (req, res) => {
  try {
    // ✅ DÜZELTME: Scope parametresini al ve kullan
    const scope = (req.query.scope || 'daily').toLowerCase();
    const data = await getAllDashboardData(scope);
    // allLogs yoksa fallback
    const allLogs = data.allLogs || (data.recentErrors && data.recentSuccess ? data.recentErrors.concat(data.recentSuccess || []) : []);
    const smsAnalytics = generateSMSAnalytics(allLogs, scope);
    res.json({
      ...smsAnalytics,
      scope,
      period: scope === 'daily' ? 'Günlük' : scope === 'monthly' ? 'Aylık' : 'Yıllık'
    });
  } catch (error) {
    console.error('❌ /api/sms/analytics error:', error);
    res.status(500).json({ error: 'Failed to get SMS analytics', details: error.message });
  }
});

app.get('/api/sms/stats', async (req, res) => {
  try {
    // ✅ DÜZELTME: Scope parametresini al ve kullan
    const scope = (req.query.scope || 'daily').toLowerCase();
    const data = await getAllDashboardData(scope);
    const smsAnalytics = generateSMSAnalytics(data.allLogs, scope);
    res.json({
      ...smsAnalytics,
      scope,
      period: scope === 'daily' ? 'Günlük' : scope === 'monthly' ? 'Aylık' : 'Yıllık'
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get SMS stats' });
  }
});

app.get('/api/sms/hourly-distribution', async (req, res) => {
  try {
    // ✅ DÜZELTME: Scope parametresini al ve kullan
    const scope = (req.query.scope || 'daily').toLowerCase();
    const data = await getAllDashboardData(scope);
    const smsData = await generateDetailedSMSAnalytics(data, scope);
    res.json(smsData.hourlyDistribution);
  } catch (error) {
    res.json([]);
  }
});

app.get('/api/sms/approval-types', async (req, res) => {
  try {
    // ✅ DÜZELTME: Scope parametresini al ve kullan
    const scope = (req.query.scope || 'daily').toLowerCase();
    debugLog('📊 SMS Approval Types endpoint called with scope:', scope);
    const data = await getAllDashboardData(scope);
    const smsData = await generateDetailedSMSAnalytics(data, scope);
    debugLog('📊 Approval types generated:', smsData.approvalTypes);
    res.json(smsData.approvalTypes);
  } catch (error) {
    debugLog('❌ Approval types error:', error);
    res.json([]);
  }
});

app.get('/api/sms/system-status', (req, res) => {
  res.json({ 
    status: 'active',
    uptime: '99.8%',
    lastCheck: new Date().toISOString()
  });
});

// ✅ Detaylı SMS tracking endpoint'i - DUPLICATE REMOVED

app.get('/api/analytics/daily-trend', async (req, res) => {
  try {
    const data = await getAllDashboardData();
    res.json(data.trends);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get daily trend' });
  }
});

app.get('/api/analytics/performance', async (req, res) => {
  try {
    const data = await getAllDashboardData();
    res.json(data.overview);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get performance' });
  }
});

app.get('/api/analytics/stores', async (req, res) => {
  try {
    const data = await getAllDashboardData();
    res.json(data.stores);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get analytics stores' });
  }
});

app.get('/api/analytics/efficiency', async (req, res) => {
  try {
    const data = await getAllDashboardData();
    
    // Gerçek efficiency hesapla: Başarılı işlem oranı
    const efficiency = data.overview.successRate || 0;
    res.json(parseFloat(efficiency));
  } catch (error) {
    res.json(0);
  }
});

app.get('/api/analytics/system', async (req, res) => {
  try {
    const data = await getAllDashboardData();
    
    // System uptime hesapla: Error oranının tersi
    const totalLogs = data.overview.todayLogs || 1;
    const errorCount = data.overview.errorCount || 0;
    const systemHealth = Math.max(0, 100 - (errorCount / totalLogs * 100));
    
    res.json(`${systemHealth.toFixed(1)}%`);
  } catch (error) {
    res.json('99.9%');
  }
});



app.get('/api/logs/stats', async (req, res) => {
  try {
    const { scope } = req.query;
    debugLog('🔍 /api/logs/stats called with scope:', scope);
    
    // Scope'a göre veri al
    const data = await getAllDashboardData(scope || 'daily');
    const allLogs = data.allLogs || [];
    
    debugLog(`🔍 /api/logs/stats - Found ${allLogs.length} logs for scope: ${scope}`);
    
    // Log istatistikleri hesapla
    const stats = {
      total: allLogs.length,
      error: allLogs.filter(log => log.level === 'ERROR').length,
      warning: allLogs.filter(log => log.level === 'WARNING').length,
      info: allLogs.filter(log => log.level === 'INFO').length,
      success: allLogs.filter(log => log.level === 'SUCCESS').length
    };
    
    debugLog('🔍 /api/logs/stats FINAL RESPONSE:', stats);
    
    res.json(stats);
    
  } catch (error) {
    debugLog('❌ Get logs stats error:', error);
    res.status(500).json({ error: 'Failed to get logs stats' });
  }
});

app.get('/api/logs/categories', async (req, res) => {
  try {
    await ensureLogsDir();
    
    // ✅ DÜZELTME: Hiyerarşik yapıdan logları oku
    const now = new Date();
    const sevenDaysAgo = new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));
    
    // Hiyerarşik yapıdan logları oku
    const allLogs = await readLogsFromHierarchicalStructure(sevenDaysAgo, now);
    
    debugLog(`🔍 /api/logs/categories - Found ${allLogs.length} logs from hierarchical structure`);
    
    // Gerçek kategorileri bul
    const categories = [...new Set(allLogs.map(log => log.category).filter(Boolean))];
    
    res.json(categories);
    
  } catch (error) {
    debugLog('❌ Get categories error:', error);
    res.json(['SYSTEM', 'SMS_APPROVAL', 'SMS_NOTIFICATION', 'SMS_VERIFICATION_DATA', 'CUSTOMER_CREATE', 'VALIDATION', 'NAVIGATION']);
  }
});

// Logs endpoint - Get all logs with filters
app.get('/api/logs', async (req, res) => {
  try {
    const { level, category, search, scope } = req.query;
    debugLog('🔍 /api/logs called with filters:', { level, category, search, scope });
    
    // Scope'a göre veri al
    const data = await getAllDashboardData(scope || 'daily');
    let logs = data.allLogs || [];
    
    debugLog('🔍 Total logs from getAllDashboardData:', logs.length);
    
    // Filtreleme
    if (level && level !== 'all') {
      logs = logs.filter(log => log.level === level);
      debugLog('�� After level filter:', logs.length);
    }
    
    if (category && category !== 'all') {
      logs = logs.filter(log => log.category === category);
      debugLog('🔍 After category filter:', logs.length);
    }
    
    if (search) {
      const searchLower = search.toLowerCase();
      logs = logs.filter(log => 
        log.message?.toLowerCase().includes(searchLower) ||
        log.store_code?.toLowerCase().includes(searchLower) ||
        log.plasiyer_name?.toLowerCase().includes(searchLower)
      );
      debugLog('🔍 After search filter:', logs.length);
    }
    
    // ErrorLogs bileşeninin beklediği format
    const formattedLogs = logs.map(log => ({
      id: log.id || Math.random(),
      timestamp: log.timestamp,
      level: log.level,
      category: log.category,
      message: log.message,
      data: log.data,
      storeName: log.store_code === 'UNKNOWN' 
        ? '⚠️ Login Öncesi' 
        : (storeNames[log.store_code] || log.store_code),
      storeCode: log.store_code,
      deviceId: log.deviceId,
      plasiyerName: log.plasiyer_name,
      customerName: log.customer_name,
      customerPhone: log.customer_phone,
      smsStatus: log.sms_status,
      smsCode: log.sms_code
    }));
    
    const response = {
      logs: formattedLogs,
      count: formattedLogs.length,
      scope: scope || 'daily',
      dateRange: data.dateRange
    };
    
    debugLog('🔍 /api/logs FINAL RESPONSE:', {
      logsCount: formattedLogs.length,
      count: formattedLogs.length,
      scope: scope || 'daily',
      hasDateRange: !!data.dateRange,
      responseKeys: Object.keys(response)
    });
    
    res.json(response);
    
  } catch (error) {
    debugLog('❌ /api/logs error:', error);
    res.status(500).json({ error: 'Failed to get logs' });
  }
});

// Customer rejection reasons endpoint
app.get('/api/customer/rejection-reasons', async (req, res) => {
  try {
    // ✅ DÜZELTME: Scope parametresini al ve kullan
    const scope = (req.query.scope || 'daily').toLowerCase();
    const data = await getAllDashboardData(scope);
    
    // ✅ DÜZELTME: Tüm logları kullan, sadece recentErrors değil
    const allLogs = data.allLogs || [];
    const errorLogs = allLogs.filter(log => log.level === 'ERROR');
    
    debugLog(`🔍 Rejection reasons - scope: ${scope}, total logs: ${allLogs.length}, errors: ${errorLogs.length}`);
    
    // Red sebeplerini analiz et
    const rejectionReasons = generateRejectionReasonsAnalysis(errorLogs);
    
    res.json(rejectionReasons);
  } catch (error) {
    debugLog('❌ Rejection reasons error:', error);
    res.status(500).json({ error: 'Failed to get rejection reasons' });
  }
});

// Customer analytics endpoint
app.get('/api/customer/analytics', async (req, res) => {
  try {
    // ✅ DÜZELTME: Scope parametresini al ve kullan
    const scope = (req.query.scope || 'daily').toLowerCase();
    const data = await getAllDashboardData(scope);
    
    // ✅ DÜZELTME: Tüm logları kullan, sadece recentErrors ve recentSuccess değil
    const allLogs = data.allLogs || [];
    const errorLogs = allLogs.filter(log => log.level === 'ERROR');
    const successLogs = allLogs.filter(log => log.level === 'SUCCESS');
    
    debugLog(`🔍 Customer analytics - scope: ${scope}, total logs: ${allLogs.length}, errors: ${errorLogs.length}, success: ${successLogs.length}`);
    
    // Müşteri analitikleri hesapla
    const customerAnalytics = generateCustomerAnalytics(errorLogs, successLogs, scope);
    
    // ✅ DÜZELTME: dateRange bilgisini ekle
    const response = {
      ...customerAnalytics,
      dateRange: data.dateRange,
      scope: scope,
      totalLogs: allLogs.length,
      errorLogs: errorLogs.length,
      successLogs: successLogs.length
    };
    
    res.json(response);
  } catch (error) {
    debugLog('❌ Customer analytics error:', error);
    res.status(500).json({ error: 'Failed to get customer analytics' });
  }
});

// SMS Analytics endpoint - SMS istatistikleri
app.get('/api/sms/analytics', async (req, res) => {
  try {
    const { scope } = req.query;
    debugLog('📊 SMS Analytics endpoint called with scope:', scope);
    
    // Scope'a göre veri al
    const data = await getAllDashboardData(scope || 'daily');
    
    // SMS analitikleri hesapla
    const smsStats = generateSMSAnalytics(data.allLogs, scope || 'daily');
    
    res.json(smsStats);
  } catch (error) {
    debugLog('❌ SMS Analytics failed:', error);
    res.status(500).json({ 
      error: 'SMS analytics failed',
      details: error.message 
    });
  }
});

// SMS Approval Types endpoint - Onay tipleri
app.get('/api/sms/approval-types', async (req, res) => {
  try {
    const { scope } = req.query;
    debugLog('📊 SMS Approval Types endpoint called with scope:', scope);
    
    // Scope'a göre veri al
    const data = await getAllDashboardData(scope || 'daily');
    
    // Detaylı SMS analitikleri hesapla
    const detailedData = await generateDetailedSMSAnalytics(data, scope || 'daily');
    
    res.json(detailedData.approvalTypes);
  } catch (error) {
    debugLog('❌ SMS Approval Types failed:', error);
    res.status(500).json({ 
      error: 'SMS approval types failed',
      details: error.message 
    });
  }
});

// SMS System Status endpoint - Sistem durumu
app.get('/api/sms/system-status', async (req, res) => {
  try {
    debugLog('📊 SMS System Status endpoint called');
    
    // Sistem durumu bilgileri
    const systemStatus = {
      status: 'active',
      uptime: '99.9%',
      lastCheck: new Date().toISOString(),
      smsService: 'operational',
      apiVersion: '1.0'
    };
    
    res.json(systemStatus);
  } catch (error) {
    debugLog('❌ SMS System Status failed:', error);
    res.status(500).json({ 
      error: 'SMS system status failed',
      details: error.message 
    });
  }
});

// SMS Detailed endpoint - SMS detaylı verileri (stats + logs)
app.get('/api/sms/detailed', async (req, res) => {
  try {
    const { scope } = req.query;
    debugLog('📊 SMS Detailed endpoint called with scope:', scope);
    
    // Scope'a göre veri al
    const data = await getAllDashboardData(scope || 'daily');
    
    // ✅ DÜZELTME: Doğru SMS analitik fonksiyonunu kullan
    const allLogs = data.allLogs || (data.recentErrors && data.recentSuccess ? data.recentErrors.concat(data.recentSuccess || []) : []);
    const smsStats = generateSMSAnalytics(allLogs, scope || 'daily');
    
    // SMS loglarını filtrele
    const smsLogs = allLogs.filter(log => 
      log.category === 'SMS_APPROVAL' || 
      log.category === 'SMS_NOTIFICATION' || 
      log.category === 'SMS_VERIFICATION_DATA'
    );
    
    debugLog('📊 SMS Detailed - smsStats:', smsStats);
    debugLog('📊 SMS Detailed - smsLogs.length:', smsLogs.length);
    
    res.json({
      stats: smsStats,
      logs: smsLogs,
      scope: scope || 'daily',
      period: scope === 'daily' ? 'Günlük' : scope === 'monthly' ? 'Aylık' : 'Yıllık'
    });
  } catch (error) {
    debugLog('❌ SMS Detailed failed:', error);
    res.status(500).json({ 
      error: 'SMS detailed data failed',
      details: error.message 
    });
  }
});

// SMS Hourly Distribution endpoint - SMS saatlik dağılımı
app.get('/api/sms/hourly-distribution', async (req, res) => {
  try {
    const { scope } = req.query;
    debugLog('📊 SMS Hourly Distribution endpoint called with scope:', scope);
    
    await ensureLogsDir();
    
    // Scope'a göre tarih aralığı hesapla
    const now = new Date();
    let startDate, endDate;
    
    if (scope === 'yearly') {
      startDate = new Date(Date.UTC(now.getFullYear(), 0, 1));
      endDate = now;
    } else if (scope === 'monthly') {
      startDate = new Date(Date.UTC(now.getFullYear(), now.getMonth(), 1));
      endDate = now;
    } else {
      // Daily - sadece bugün
      startDate = new Date(Date.UTC(now.getFullYear(), now.getMonth(), now.getDate()));
      endDate = new Date(Date.UTC(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59, 59, 999));
    }
    
    // Hiyerarşik yapıdan logları oku
    const allLogs = await readLogsFromHierarchicalStructure(startDate, endDate);
    
    // SMS loglarını filtrele
    const smsLogs = allLogs.filter(log => 
      log.category === 'SMS_APPROVAL' || 
      log.category === 'SMS_NOTIFICATION' || 
      log.category === 'SMS_VERIFICATION_DATA'
    );
    
    // ✅ DÜZELTME: Saatlik dağılım hesapla - Tüm SMS aktivitelerini dahil et
    const hourlyDistribution = [];
    for (let hour = 0; hour < 24; hour++) {
      const hourLogs = smsLogs.filter(log => {
        const logHour = new Date(log.timestamp).getHours();
        return logHour === hour;
      });
      
      hourlyDistribution.push({
        hour: hour.toString().padStart(2, '0') + ':00',
        count: hourLogs.length
      });
    }
    
    debugLog('🔍 Saatlik Dağılım DEBUG:', {
      scope: scope || 'daily',
      dateRange: { start: startDate.toISOString(), end: endDate.toISOString() },
      totalLogs: allLogs.length,
      totalSMSLogs: smsLogs.length,
      hourlyDistribution: hourlyDistribution.filter(h => h.count > 0)
    });
    
    res.json(hourlyDistribution);
  } catch (error) {
    debugLog('❌ SMS Hourly Distribution failed:', error);
    res.status(500).json({ 
      error: 'SMS hourly distribution failed',
      details: error.message 
    });
  }
});

// SMS Error Analysis endpoint - SMS ile ilgili hataları analiz et
app.get('/api/sms/error-analysis', async (req, res) => {
  try {
    debugLog('📊 SMS Error Analysis endpoint called');
    
    await ensureLogsDir();
    
    const files = await fs.readdir(LOGS_DIR);
    const now = new Date();
    const sevenDaysAgo = new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));
    
    let allLogs = [];
    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      
      const dateStr = file.split('-').slice(0, 3).join('-');
      const fileDate = new Date(dateStr);
      
      if (fileDate >= sevenDaysAgo) {
        try {
          const data = await fs.readFile(path.join(LOGS_DIR, file), 'utf8');
          const logs = JSON.parse(data);
          allLogs.push(...logs);
        } catch (error) {
          debugLog('❌ Error reading:', error);
        }
      }
    }
    
    const smsErrorAnalysis = generateSMSErrorAnalysis(allLogs);
    
    res.json(smsErrorAnalysis);
  } catch (error) {
    debugLog('❌ SMS Error Analysis failed:', error);
    res.status(500).json({ 
      error: 'SMS error analysis failed',
      details: error.message 
    });
  }
});

// Helper function to get all dashboard data
async function getAllDashboardData(scope = 'daily') {
  debugLog(`🚀 getAllDashboardData BAŞLADI - scope: ${scope}`);
  await ensureLogsDir();
  
  // ✅ DÜZELTME: Türkçe scope parametrelerini İngilizce'ye çevir
  let normalizedScope = scope;
  if (scope === 'gunluk') normalizedScope = 'daily';
  if (scope === 'aylik') normalizedScope = 'monthly';
  if (scope === 'yillik') normalizedScope = 'yearly';
  
  // ✅ DÜZELTME: Scope'a göre tarih aralığı hesapla
  const now = new Date();
  let startDate, endDate;
  
  debugLog(`🔍 getAllDashboardData called with scope: ${scope} (normalized: ${normalizedScope})`);
  debugLog(`🔍 Current date: ${now.toISOString()}`);
  
  if (normalizedScope === 'yearly') {
    // Bu yılın başı - UTC
    startDate = new Date(Date.UTC(now.getFullYear(), 0, 1));
    endDate = now;
    debugLog(`📅 YEARLY scope selected`);
  } else if (normalizedScope === 'monthly') {
    // Bu ayın başı - UTC
    startDate = new Date(Date.UTC(now.getFullYear(), now.getMonth(), 1));
    endDate = now;
    debugLog(`📅 MONTHLY scope selected`);
    debugLog(`📅 Month: ${now.getMonth()}, Year: ${now.getFullYear()}`);
  } else {
    // Sadece bugünün logları (daily) - UTC
    startDate = new Date(Date.UTC(now.getFullYear(), now.getMonth(), now.getDate()));
    endDate = new Date(Date.UTC(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59, 59, 999));
    debugLog(`📅 DAILY scope selected (only today)`);
  }
  
  debugLog(`🔍 Calculated startDate: ${startDate.toISOString()}`);
  debugLog(`🔍 Calculated endDate: ${endDate.toISOString()}`);
  
  // Hiyerarşik yapıdan logları oku
  const allLogs = await readLogsFromHierarchicalStructure(startDate, endDate);
  
  debugLog(`🔍 getAllDashboardData scope: ${scope}, logs from ${startDate.toISOString().split('T')[0]} to ${endDate.toISOString().split('T')[0]}, total: ${allLogs.length}`);
  
  // Debug: Log dosyalarını kontrol et
  debugLog('🔍 Date range details:');
  debugLog(`   - startDate: ${startDate.toISOString()}`);
  debugLog(`   - endDate: ${endDate.toISOString()}`);
  debugLog(`   - startDate local: ${startDate.toLocaleDateString('tr-TR')}`);
  debugLog(`   - endDate local: ${endDate.toLocaleDateString('tr-TR')}`);
  
  // Debug: Log seviyelerini kontrol et
  const levelCounts = {};
  allLogs.forEach(log => {
    levelCounts[log.level] = (levelCounts[log.level] || 0) + 1;
  });
  debugLog('🔍 Log levels in allLogs:', levelCounts);
  
  // Trend verilerini hesapla
  const trendData = generateTrendData(allLogs);
  
  // Trend değişimlerini hesapla
  const trends = {
    usersChange: calculateActiveTabletsChange(trendData),
    ordersChange: calculateTodayLogsChange(trendData),
    revenueChange: calculateSuccessRateChange(trendData)
  };
  
  const result = {
    overview: generateOverviewData(allLogs),
    stores: generateStoreStats(allLogs),
    recentErrors: getRecentErrors(allLogs),
    recentSuccess: getRecentSuccess(allLogs),
    allLogs: allLogs, // ✅ Tüm logları dahil et (INFO logları için)
    smsAnalytics: generateSMSAnalytics(allLogs),
    trends: trends, // ✅ Trend değişimleri
    trendData: trendData, // ✅ Ham trend verisi
    lastUpdate: new Date().toISOString(),
    scope,
    dateRange: {
      start: startDate.toISOString(),
      end: endDate.toISOString()
    },
    logCount: allLogs.length // ✅ Toplam log sayısı
  };
  
  debugLog(`🏁 getAllDashboardData BİTTİ - scope: ${scope}, logCount: ${result.logCount}`);
  debugLog('🏁 Result dateRange:', result.dateRange);
  
  return result;
}

// ====== HELPER FUNCTIONS ======

function generateOverviewData(logs) {
  debugLog(`🔍 generateOverviewData called with ${logs.length} logs`);
  
  // ✅ DÜZELTME: Scope'a göre tüm logları kullan, sadece bugünü değil
  const today = new Date().toISOString().split('T')[0];
  debugLog(`🔍 Today: ${today}`);
  
  // Bugünün logları (sadece bugün için ayrı sayım)
  const todayLogs = logs.filter(log => {
    const logDate = log.timestamp || log.received_at;
    if (!logDate) return false;
    const logDateStr = logDate.split('T')[0];
    return logDateStr === today;
  });
  
  debugLog(`🔍 Today's logs: ${todayLogs.length}`);
  debugLog(`🔍 Total logs in scope: ${logs.length}`);
  
  // Aktif tabletler (online olanlar) - store statistics'ten al
  const storeStats = generateStoreStats(logs);
  const activeTablets = storeStats.reduce((total, store) => total + store.onlineTablets, 0);
  
  debugLog(`📱 Active tablets (online): ${activeTablets}`);
  
  // ✅ DÜZELTME: Scope içindeki tüm loglardan hata sayısı hesapla
  const errorLogCount = logs.filter(l => l.level === 'ERROR').length;
  const totalLogCount = logs.length;
  const systemSuccessRate = totalLogCount > 0 ? 
    (((totalLogCount - errorLogCount) / totalLogCount) * 100).toFixed(1) 
    : 0;

  // ✅ DÜZELTME: SMS verilerini dahil et
  const smsAnalytics = generateSMSAnalytics(logs, 'daily');
  
  // Overview objesi oluştur
  const overview = {};
  overview.totalLogs = logs.length; // ✅ Scope içindeki tüm loglar
  overview.activeTablets = activeTablets;
  overview.todayLogs = todayLogs.length; // ✅ Sadece bugünün logları (ayrı sayım)
  overview.errorCount = errorLogCount; // ✅ Scope içindeki hata sayısı
  overview.successCount = logs.filter(l => l.level === 'SUCCESS').length; // ✅ Scope içindeki başarı sayısı
  overview.warningCount = logs.filter(l => l.level === 'WARNING').length; // ✅ Scope içindeki uyarı sayısı
  overview.successRate = systemSuccessRate;
  
  // ✅ SMS verilerini ekle
  overview.smsSent = smsAnalytics.totalSent;
  overview.smsSuccess = smsAnalytics.totalSuccess;
  overview.smsFailed = smsAnalytics.totalFailed;
  overview.smsSuccessRate = smsAnalytics.successRate;
  
  // ✅ DÜZELTME: Plasiyer ve müşteri isimlerini ekle
  // Son başarılı müşteri oluşturma logundan bilgileri al
  const lastCustomerLog = logs
    .filter(log => log.category === 'CUSTOMER_CREATE' && log.level === 'SUCCESS')
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];
  
  overview.plasiyerName = lastCustomerLog?.plasiyer_name || 'N/A';
  overview.customerName = lastCustomerLog?.data?.customerName || lastCustomerLog?.data?.fullName || 'N/A';
  
  debugLog(`📊 Overview object created:`, overview);
  debugLog(`🔍 overview.totalLogs = ${overview.totalLogs}`);
  debugLog(`🔍 logs.length = ${logs.length}`);
  debugLog(`📱 SMS data in overview:`, {
    smsSent: overview.smsSent,
    smsSuccess: overview.smsSuccess,
    smsFailed: overview.smsFailed,
    smsSuccessRate: overview.smsSuccessRate
  });
  
  return overview;
}

function generateStoreStats(logs) {
  const storeStats = {};
  const deviceTracker = {}; // 📱 Global cihaz takibi (store agnostic)
  const now = new Date();
  const fifteenMinutesAgo = new Date(now.getTime() - 10 * 60 * 1000); // ⏰ 10 dakika
  
  debugLog(`🔍 Analyzing ${logs.length} logs for store statistics...`);
  
  // 1️⃣ AŞAMA: Global cihaz bazlı analiz (son kullanım yeri)
  logs.forEach(log => {
    const storeCode = log.store_code;
    const deviceId = log.device_id || 'UNKNOWN_DEVICE';
    
    // ✅ DÜZELTME: Sadece gerçek mağaza kodları olan logları dahil et
    if (!storeCode || storeCode === 'UNKNOWN') return;
    
    // 🔄 Global device tracking - sadece device_id bazında
    if (!deviceTracker[deviceId]) {
      deviceTracker[deviceId] = {
        deviceId,
        currentStoreCode: storeCode, // 🎯 En son kullanıldığı mağaza
        lastActivity: null,
        logCount: 0,
        isOnline: false,
        lastLogTime: null,
        storeHistory: [], // Hangi store'larda kullanıldığını takip et
        storeLogCounts: {}, // Her store'daki log sayısı
        storeLastActivity: {} // 🆕 Her store'daki son aktivite zamanı
      };
    }
    
    const device = deviceTracker[deviceId];
    device.logCount++;
    
    // Her store'daki log sayısını takip et
    if (!device.storeLogCounts[storeCode]) {
      device.storeLogCounts[storeCode] = 0;
    }
    device.storeLogCounts[storeCode]++;
    
    // Son aktivite zamanını güncelle
    const logTime = new Date(log.timestamp || log.received_at);
    
    // 🆕 Her store'daki son aktivite zamanını takip et
    if (!device.storeLastActivity[storeCode] || logTime > device.storeLastActivity[storeCode]) {
      device.storeLastActivity[storeCode] = logTime;
    }
    if (!device.lastActivity || logTime > device.lastActivity) {
      device.lastActivity = logTime; // <-- Artık Date objesi olarak saklanıyor
      // ✅ Geçersiz timestamp formatlarını düzelt
      let cleanTimestamp = log.timestamp || log.received_at;
      if (cleanTimestamp && cleanTimestamp.includes('.3NZ')) {
        cleanTimestamp = cleanTimestamp.replace('.3NZ', '.000Z');
      }
      device.lastLogTime = cleanTimestamp;
      device.currentStoreCode = storeCode; // 🎯 En son hangi store'da kullanıldı
    }
    
    // Store history'ye ekle (unique)
    if (!device.storeHistory.includes(storeCode)) {
      device.storeHistory.push(storeCode);
    }
    
    // Online durumu: En son aktivite zamanına göre hesapla (her cihaz için)
    device.isOnline = device.lastActivity > fifteenMinutesAgo;

    // 🔍 DEBUG: Online durumu hesaplama detayları
    debugLog(`\n🔍 DEBUG: Device ${device.deviceId} online calculation:`);
    debugLog(`   lastActivity: ${device.lastActivity}`);
    debugLog(`   fifteenMinutesAgo: ${fifteenMinutesAgo}`);
    debugLog(`   isOnline: ${device.isOnline}`);
    debugLog(`   timeDiff: ${device.lastActivity - fifteenMinutesAgo}ms`);
    debugLog(`   current time: ${now}`);
    debugLog(`   lastActivity is Date: ${device.lastActivity instanceof Date}`);
    debugLog(`   fifteenMinutesAgo is Date: ${fifteenMinutesAgo instanceof Date}`);
    debugLog(`🔍 DEBUG END\n`);
  });
  
  // 2️⃣ AŞAMA: Store bazlı istatistikler
  logs.forEach(log => {
    const storeCode = log.store_code;
    
    // ✅ DÜZELTME: Sadece gerçek mağaza kodları olan logları dahil et
    if (!storeCode || storeCode === 'UNKNOWN') return;
    
    if (!storeStats[storeCode]) {
      storeStats[storeCode] = {
        storeCode,
        storeName: storeNames[storeCode] || `Store ${storeCode}`,
        totalLogs: 0,
        errorCount: 0,
        successCount: 0,
        customerCount: 0,
        lastActivity: null,
        status: 'inactive',
        // 🆕 Tablet tracking bilgileri
        totalTablets: 0,
        onlineTablets: 0,
        offlineTablets: 0,
        tabletDetails: []
      };
    }
    
    const store = storeStats[storeCode];
    store.totalLogs++;
    
    if (log.level === 'ERROR') store.errorCount++;
    if (log.level === 'SUCCESS') store.successCount++;
    
    // Müşteri sayısı hesaplama
    if (log.category === 'CUSTOMER_CREATE' && log.level === 'SUCCESS' && 
        log.message === 'Customer account created successfully') {
      store.customerCount++;
    }
    
    // Store'un genel son aktivitesi
    if (!store.lastActivity || log.timestamp > store.lastActivity) {
      // ✅ Geçersiz timestamp formatlarını düzelt (.3NZ -> .000Z)
      let cleanTimestamp = log.timestamp;
      if (cleanTimestamp && cleanTimestamp.includes('.3NZ')) {
        cleanTimestamp = cleanTimestamp.replace('.3NZ', '.000Z');
      }
      store.lastActivity = cleanTimestamp || log.received_at;
    }
  });
  
  // 3️⃣ AŞAMA: Tablet bilgilerini store'lara ata (YENİ MANTIK)
  Object.values(deviceTracker).forEach(device => {
    // 🎯 YENİ MANTIK: Tablet sadece en son kullanıldığı mağazada aktif sayılır
    const currentStoreCode = device.currentStoreCode;
    const currentStore = storeStats[currentStoreCode];
    
    if (!currentStore) return;
    
    // 🔍 Device ID'yi düzelt - UNKNOWN_DEVICE'ları göster
    let displayDeviceId = device.deviceId;
    if (device.deviceId === 'UNKNOWN_DEVICE') {
      displayDeviceId = `Tablet-${currentStore.totalTablets + 1}`;
    }
    
    // 🎯 Bu store'daki log sayısını al
    const currentStoreLogCount = device.storeLogCounts[currentStoreCode] || 0;
    
    // Tablet detaylarını ekle (sadece current store'a)
    const existingTablet = currentStore.tabletDetails.find(t => t.originalDeviceId === device.deviceId);
    if (!existingTablet) {
      currentStore.tabletDetails.push({
        deviceId: displayDeviceId, // Sadece device ID
        originalDeviceId: device.deviceId, // Orijinal ID
        isOnline: device.isOnline,
        lastActivity: device.lastLogTime,
        logCount: currentStoreLogCount, // 🎯 Sadece bu store'daki loglar
        totalLogCount: device.logCount, // 🔍 Tüm store'lardaki loglar (debug için)
        statusIcon: device.isOnline ? '🟢' : '🔴',
        statusText: device.isOnline ? 'Online' : 'Offline',
        lastSeenMinutes: Math.floor((now - device.storeLastActivity[currentStoreCode]) / (1000 * 60)),
        isUnknownDevice: device.deviceId === 'UNKNOWN_DEVICE',
        // 🆕 Multi-store bilgileri
        isMultiStore: device.storeHistory.length > 1,
        storeHistory: device.storeHistory,
        currentStore: device.currentStoreCode,
        // 🆕 Yeni bilgiler
        isCurrentStore: device.isOnline, // Sadece online tabletler aktif sayılır
        previousStores: device.storeHistory.filter(s => s !== currentStoreCode)
      });
      
      currentStore.totalTablets++;
    }
    
    // 🎯 YENİ MANTIK: Tablet sadece current store'da online sayılır
    if (device.isOnline) {
      currentStore.onlineTablets++;
    } else {
      currentStore.offlineTablets++;
    }
    
    // 🔍 Diğer store'larda bu tablet'in geçmiş kullanımını göster
    device.storeHistory.forEach(storeCode => {
      if (storeCode === currentStoreCode) return; // Current store'u atla
      
      const store = storeStats[storeCode];
      if (!store) return;
      
      const previousStoreLogCount = device.storeLogCounts[storeCode] || 0;
      
      // Geçmiş kullanım bilgisini ekle
      store.tabletDetails.push({
        deviceId: displayDeviceId,
        originalDeviceId: device.deviceId,
        isOnline: false, // Geçmiş kullanım olduğu için offline
        lastActivity: device.lastLogTime,
        logCount: previousStoreLogCount,
        totalLogCount: device.logCount,
        statusIcon: '🔴',
        statusText: 'Geçmiş Kullanım',
        lastSeenMinutes: Math.floor((now - device.storeLastActivity[storeCode]) / (1000 * 60)),
        isUnknownDevice: device.deviceId === 'UNKNOWN_DEVICE',
        isMultiStore: device.storeHistory.length > 1,
        storeHistory: device.storeHistory,
        currentStore: device.currentStoreCode,
        isCurrentStore: false, // Bu tablet bu mağazada aktif değil
        previousStores: device.storeHistory.filter(s => s !== storeCode)
      });
      
      store.totalTablets++;
      store.offlineTablets++; // Geçmiş kullanım olduğu için offline
    });
  });
  
  // 4️⃣ AŞAMA: Mağaza durumunu belirle (YENİ MANTIK)
  Object.values(storeStats).forEach(store => {
    // 🎯 YENİ MANTIK: Mağaza durumu sadece o mağazada aktif tablet varsa "active"
    if (store.totalTablets > 0) {
      if (store.onlineTablets > 0) {
        store.status = 'active'; // ✅ Bu mağazada online tablet var
      } else {
        // 🔍 Geçmiş kullanım tabletleri var mı kontrol et
        const hasHistoricalTablets = store.tabletDetails.some(tablet => 
          !tablet.isCurrentStore && tablet.logCount > 0
        );
        
        if (hasHistoricalTablets) {
          store.status = 'inactive'; // ⚠️ Sadece geçmiş kullanım tabletleri var
        } else {
          store.status = 'unknown'; // ❓ Hiç tablet bilgisi yok
        }
      }
    } else {
      // 📱 Tablet bilgisi yoksa sadece log aktivitesine bak
      if (store.totalLogs > 0) {
        const threeHoursAgo = new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString();
        const hasRecentActivity = store.lastActivity && store.lastActivity > threeHoursAgo;
        
        if (hasRecentActivity) {
          store.status = 'active'; // Son 3 saat içinde aktivite var
        } else {
          store.status = 'inactive'; // Log var ama eski
        }
      } else {
        store.status = 'unknown'; // ❓ Hiç log yok
      }
    }
    
    // Hata oranı yüksekse durum güncelle
    if (store.errorCount > 10 && store.totalLogs > 0) {
      const errorRate = (store.errorCount / store.totalLogs) * 100;
      if (errorRate > 50) {
        store.status = 'error';
      }
    }
  });
  
  const storeArray = Object.values(storeStats);
  
  // 📊 Debug log'u - Device tracking detayları
  debugLog(`🏪 Store Statistics Generated:`);
  debugLog(`🔍 Global Device Tracker Summary:`, Object.keys(deviceTracker).length, 'unique devices found');
  Object.values(deviceTracker).forEach(device => {
    const multiStoreTag = device.storeHistory.length > 1 ? ` [MULTI-STORE: ${device.storeHistory.join(',')}]` : '';
    debugLog(`   📱 Device ${device.deviceId}: Currently at ${device.currentStoreCode} (${device.logCount} logs, ${device.isOnline ? 'Online' : 'Offline'})${multiStoreTag}`);
  });
  
  storeArray.forEach(store => {
    debugLog(`📊 ${store.storeName}: ${store.onlineTablets}/${store.totalTablets} tablets online, ${store.customerCount} customers, Status: ${store.status}`);
    store.tabletDetails.forEach(tablet => {
      const currentStoreTag = tablet.isCurrentStore ? ' [CURRENT]' : ' [HISTORICAL]';
      const multiStoreTag = tablet.isMultiStore ? ` [Used in: ${tablet.storeHistory.join(',')}]` : '';
      const logInfo = tablet.totalLogCount && tablet.totalLogCount !== tablet.logCount 
        ? ` (${tablet.logCount}/${tablet.totalLogCount} logs)` 
        : ` (${tablet.logCount} logs)`;
      debugLog(`   📱 Device ${tablet.originalDeviceId}: ${tablet.statusIcon} ${tablet.statusText}${currentStoreTag} (${tablet.lastSeenMinutes}m ago)${logInfo}${multiStoreTag}`);
    });
    
    // 🔍 Tablet bilgisi yoksa debug yap
    if (store.totalTablets === 0 && store.totalLogs > 0) {
      debugLog(`   ⚠️  WARNING: Store has ${store.totalLogs} logs but no tablet details!`);
      debugLog(`   🔍 Device tracking might be failing - check device_id field in logs`);
    }
  });
  
  return storeArray;
}

function getRecentErrors(logs) {
  return logs
    .filter(log => log.level === 'ERROR')
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 10)
    .map(log => ({
      ...log,
      storeName: storeNames[log.store_code] || log.store_code
    }));
}

function getRecentSuccess(logs) {
  return logs
    .filter(log => log.level === 'SUCCESS')
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 10)
    .map(log => ({
      ...log,
      storeName: log.store_code === 'UNKNOWN' 
        ? '⚠️ Login Öncesi' 
        : (storeNames[log.store_code] || log.store_code)
    }));
}

function generateSMSAnalytics(logs, scope = 'daily') {
  debugLog(`🔍 generateSMSAnalytics called with ${logs.length} logs, scope: ${scope}`);
  
  // ✅ SMS_APPROVAL, SMS_NOTIFICATION ve SMS_VERIFICATION_DATA kategorilerini dahil et
  const smsLogs = logs.filter(log => 
    log.category === 'SMS_APPROVAL' || 
    log.category === 'SMS_NOTIFICATION' || 
    log.category === 'SMS_VERIFICATION_DATA'
  );
  
  debugLog(`🔍 SMS logs found: ${smsLogs.length}`);
  
  // ✅ DÜZELTME: Sadece gerçek SMS gönderim mesajlarını say (çift sayımı önle)
  const sentSuccesses = smsLogs.filter(log => 
    log.message.includes('SMS sent successfully') ||
    log.message.includes('Customer account SMS sent successfully') ||
    log.message.includes('Account creation SMS sent successfully') ||
    log.message.includes('SMS code request started') ||
    log.message.includes('Send Account SMS started')
  ).length;
  
  // ✅ DÜZELTME: Sadece başarılı doğrulama mesajlarını say
  const verificationSuccesses = smsLogs.filter(log => 
    log.message.includes('Primary phone SMS verification successful') ||
    log.message.includes('SMS verification successful') ||
    log.message.includes('verification successful') ||
    log.message.includes('Sözleşme onay SMS doğrulama başarılı') ||
    log.message.includes('KVK izni doğrulama başarılı') ||
    log.message.includes('Ticari ileti onayı doğrulama başarılı') ||
    log.message.includes('İkinci telefon doğrulama başarılı')
  ).length;
  
  // ✅ DÜZELTME: totalSent = sentSuccesses (sadece gönderim sayısı)
  const totalSent = sentSuccesses;
  const totalSuccess = verificationSuccesses;

  // ✅ DÜZELTME: Sadece SMS doğrulama hatalarını say
  const verificationFailures = smsLogs.filter(log => 
    log.level === 'ERROR' && 
    (log.message.includes('SMS verification rejected') ||
     log.message.includes('verification rejected') ||
     log.message.includes('Wrong code') ||
     log.message.includes('Sözleşme onay SMS doğrulama başarısız') ||
     log.message.includes('Sözleşme onay SMS doğrulama reddedildi') ||
     log.message.includes('KVK izni doğrulama başarısız') ||
     log.message.includes('Ticari ileti onayı doğrulama başarısız') ||
     log.message.includes('İkinci telefon doğrulama başarısız') ||
     log.message.includes('SMS gönderme başarısız') ||
     log.message.includes('SMS gönderme hatası'))
  ).length;

  debugLog('🔍 SMS Analytics DEBUG:', {
    originalLogs: smsLogs.length,
    sentSuccesses,
    verificationSuccesses,
    verificationFailures,
    totalSent,
    totalSuccess,
    levelDistribution: {
      INFO: smsLogs.filter(log => log.level === 'INFO').length,
      SUCCESS: smsLogs.filter(log => log.level === 'SUCCESS').length,
      ERROR: smsLogs.filter(log => log.level === 'ERROR').length
    },
    sentMessages: smsLogs.filter(log => 
      log.message.includes('SMS sent successfully') ||
      log.message.includes('Customer account SMS sent successfully') ||
      log.message.includes('Account creation SMS sent successfully') ||
      log.message.includes('SMS code request started') ||
      log.message.includes('Send Account SMS started')
    ).map(log => log.message),
    verificationMessages: smsLogs.filter(log => 
      log.message.includes('Primary phone SMS verification successful') ||
      log.message.includes('SMS verification successful') ||
      log.message.includes('verification successful') ||
      log.message.includes('Sözleşme onay SMS doğrulama başarılı') ||
      log.message.includes('KVK izni doğrulama başarılı') ||
      log.message.includes('Ticari ileti onayı doğrulama başarılı') ||
      log.message.includes('İkinci telefon doğrulama başarılı')
    ).map(log => log.message),
    sampleMessages: smsLogs.slice(0, 5).map(log => ({
      message: log.message,
      level: log.level,
      category: log.category
    }))
  });
  
  return {
    totalSent: totalSent,  // ✅ Düzeltildi: Sadece gönderim sayısı
    totalSuccess: totalSuccess,  // ✅ Düzeltildi: Sadece doğrulama başarıları
    totalFailed: verificationFailures,  // ✅ Düzeltildi: Sadece doğrulama hataları
    successRate: totalSent > 0 ? 
      ((totalSuccess / totalSent) * 100).toFixed(1) 
      : (totalSuccess > 0 ? '100.0' : '0.0')  // ✅ Doğrulama başarı oranı
  };
}

// ✅ Detaylı SMS analitikleri fonksiyonu
async function generateDetailedSMSAnalytics(data = null, scope = 'daily') {
  let allLogs = [];
  
  if (data) {
    // Eğer data parametresi verilmişse, onu kullan
    allLogs = data.recentErrors.concat(data.recentSuccess || []);
  } else {
    // Eski yöntem - scope'a göre tarih aralığı hesapla
    await ensureLogsDir();
    
    const now = new Date();
    let startDate, endDate;
    
     if (scope === 'yearly') {
      // Bu yılın başı - UTC
      startDate = new Date(Date.UTC(now.getFullYear(), 0, 1));
      endDate = now;
    } else if (scope === 'monthly') {
      // Bu ayın başı - UTC
      startDate = new Date(Date.UTC(now.getFullYear(), now.getMonth(), 1));
      endDate = now;
    } else {
      // Son 7 gün (daily)
      startDate = new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));
      endDate = now;
    }
    
    // Hiyerarşik yapıdan logları oku
    allLogs = await readLogsFromHierarchicalStructure(startDate, endDate);
    
    debugLog(`📱 SMS Analytics scope: ${scope}, logs from ${startDate.toISOString().split('T')[0]} to ${endDate.toISOString().split('T')[0]}, total: ${allLogs.length}`);
  }
  
  const smsLogs = allLogs.filter(log => 
    log.category === 'SMS_APPROVAL' || 
    log.category === 'SMS_NOTIFICATION' || 
    log.category === 'SMS_VERIFICATION_DATA'
  );
  
  // ✅ Çift kayıtları önle - aynı telefon ve onay adımı için tek kayıt
  const uniqueSMSLogs = [];
  const seenKeys = new Set();
  
  smsLogs.forEach(log => {
    // Benzersiz anahtar oluştur: telefon + onay adımı + mesaj tipi
    const phoneNumber = log.phoneNumber || log.data?.phoneNumber || 'Unknown';
    const approvalStep = log.data?.approvalStep || log.data?.type || 'Unknown';
    const messageType = log.message.includes('verification successful') ? 'verification' : 'sent';
    const key = `${phoneNumber}-${approvalStep}-${messageType}`;
    
    // Eğer bu anahtar daha önce görülmemişse ekle
    if (!seenKeys.has(key)) {
      seenKeys.add(key);
      uniqueSMSLogs.push(log);
    }
  });
  
  // ✅ DÜZELTME: Saatlik dağılım hesapla - Tüm SMS aktivitelerini dahil et
  const hourlyDistribution = [];
  for (let hour = 0; hour < 24; hour++) {
    const hourLogs = smsLogs.filter(log => {
      const logHour = new Date(log.timestamp).getHours();
      return logHour === hour;
    });
    
    hourlyDistribution.push({
      hour: hour.toString().padStart(2, '0') + ':00',
      count: hourLogs.length
    });
  }
  
  debugLog('🔍 Saatlik Dağılım DEBUG:', {
    totalSMSLogs: smsLogs.length,
    hourlyDistribution: hourlyDistribution.filter(h => h.count > 0)
  });
  
  // ✅ Onay tipleri analizi - sadece başarılı gönderim mesajlarını say (double counting önlendi)
  
  // Debug için sözleşme onayı loglarını kontrol et
  const sozlesmeOnayLogs = uniqueSMSLogs.filter(log => 
    log.category === 'SMS_APPROVAL' && 
    log.message.includes('SMS sent successfully') &&
    (log.data?.approvalStep?.includes('1_Sozlesme_Onayi') || 
     log.data?.type === 'first')
  );
  
  debugLog('🔍 Sözleşme Onayı DEBUG:', {
    totalSMSLogs: smsLogs.length,
    uniqueSMSLogs: uniqueSMSLogs.length,
    duplicatesRemoved: smsLogs.length - uniqueSMSLogs.length,
    successSMSLogs: uniqueSMSLogs.filter(log => log.level === 'SUCCESS').length,
    sentSuccessfully: uniqueSMSLogs.filter(log => log.message.includes('SMS sent successfully')).length,
    sozlesmeOnayCount: sozlesmeOnayLogs.length,
    sozlesmeOnayLogSamples: sozlesmeOnayLogs.slice(0, 3).map(log => ({
      message: log.message,
      level: log.level,
      category: log.category,
      approvalStep: log.data?.approvalStep,
      type: log.data?.type
    }))
  });
  
  // ✅ Onay tiplerini daha detaylı hesapla
  const sozlesmeOnayCount = uniqueSMSLogs.filter(log => 
    log.category === 'SMS_APPROVAL' && 
    log.message.includes('SMS sent successfully') &&
    (log.data?.approvalStep?.includes('1_Sozlesme_Onayi') || 
     log.data?.type === 'first')
  ).length;
  
  const kisiselVeriCount = uniqueSMSLogs.filter(log => 
    log.category === 'SMS_APPROVAL' && 
    log.message.includes('SMS sent successfully') &&
    (log.data?.approvalStep?.includes('2_Kisisel_Veri_Izni') || 
     log.data?.type === 'first2')
  ).length;
  
  const ticariIletiCount = uniqueSMSLogs.filter(log => 
    log.category === 'SMS_APPROVAL' && 
    log.message.includes('SMS sent successfully') &&
    (log.data?.approvalStep?.includes('3_Ticari_Ileti_Onayi') || 
     log.data?.type === 'first3')
  ).length;
  
  const ikinciTelefonCount = uniqueSMSLogs.filter(log => 
    log.category === 'SMS_APPROVAL' && 
    log.message.includes('SMS sent successfully') &&
    (log.data?.approvalStep?.includes('Ikinci_Telefon') || 
     log.data?.type === 'second')
  ).length;
  
  const hesapBildirimCount = uniqueSMSLogs.filter(log => 
    log.category === 'SMS_NOTIFICATION' && 
    log.message.includes('SMS sent successfully')
  ).length;
  
  // ✅ DÜZELTME: SMS istatistiklerini doğru hesapla
  const sentSuccesses = uniqueSMSLogs.filter(log => 
    log.message.includes('SMS sent successfully') ||
    log.message.includes('Customer account SMS sent successfully') ||
    log.message.includes('Account creation SMS sent successfully') ||
    log.message.includes('SMS code request started') ||
    log.message.includes('Send Account SMS started')
  ).length;
  
  const verificationSuccesses = uniqueSMSLogs.filter(log => 
    log.message.includes('Primary phone SMS verification successful') ||
    log.message.includes('SMS verification successful') ||
    log.message.includes('verification successful') ||
    log.message.includes('Sözleşme onay SMS doğrulama başarılı') ||
    log.message.includes('KVK izni doğrulama başarılı') ||
    log.message.includes('Ticari ileti onayı doğrulama başarılı') ||
    log.message.includes('İkinci telefon doğrulama başarılı')
  ).length;
  
  const verificationFailures = uniqueSMSLogs.filter(log => 
    log.level === 'ERROR' && 
    (log.message.includes('SMS verification rejected') ||
     log.message.includes('verification rejected') ||
     log.message.includes('Wrong code') ||
     log.message.includes('Sözleşme onay SMS doğrulama başarısız') ||
     log.message.includes('Sözleşme onay SMS doğrulama reddedildi') ||
     log.message.includes('KVK izni doğrulama başarısız') ||
     log.message.includes('Ticari ileti onayı doğrulama başarısız') ||
     log.message.includes('İkinci telefon doğrulama başarısız') ||
     log.message.includes('SMS gönderme başarısız') ||
     log.message.includes('SMS gönderme hatası'))
  ).length;
  
  const totalSent = sentSuccesses;
  const totalSuccess = verificationSuccesses;
  const totalFailed = verificationFailures;
  
  // ✅ Kategorize edilmemiş SMS'leri bul
  const categorizedCount = sozlesmeOnayCount + kisiselVeriCount + ticariIletiCount + ikinciTelefonCount + hesapBildirimCount;
  const uncategorizedCount = sentSuccesses - categorizedCount;
  
  debugLog('�� Onay Tipleri DEBUG:', {
    totalSuccessSMS: sentSuccesses,
    sozlesmeOnayCount,
    kisiselVeriCount,
    ticariIletiCount,
    ikinciTelefonCount,
    hesapBildirimCount,
    categorizedCount,
    uncategorizedCount,
    allSuccessSMS: uniqueSMSLogs.filter(log => 
      log.message.includes('SMS sent successfully') ||
      log.message.includes('Customer account SMS sent successfully') ||
      log.message.includes('SMS verification successful') ||
      log.message.includes('verification successful') ||
      log.message.includes('Sözleşme onay SMS doğrulama başarılı') ||
      log.message.includes('KVK izni doğrulama başarılı') ||
      log.message.includes('Ticari ileti onayı doğrulama başarılı') ||
      log.message.includes('İkinci telefon doğrulama başarılı')
    ).map(log => ({
      message: log.message,
      category: log.category,
      approvalStep: log.data?.approvalStep,
      type: log.data?.type,
      level: log.level
    }))
  });
  
  const approvalTypes = [
    {
      name: 'Sözleşme Onayı',
      value: sozlesmeOnayCount
    },
    {
      name: 'Kişisel Veri İzni', 
      value: kisiselVeriCount
    },
    {
      name: 'Ticari İletişim',
      value: ticariIletiCount
    },
    {
      name: 'İkinci Telefon',
      value: ikinciTelefonCount
    },
    {
      name: 'Hesap Bildirimi',
      value: hesapBildirimCount
    }
  ];
  
  // ✅ Eğer kategorize edilmemiş SMS varsa, onları da ekle
  if (uncategorizedCount > 0) {
    approvalTypes.push({
      name: 'Diğer SMS',
      value: uncategorizedCount
    });
  }
  
  const stats = {
    totalSent: totalSent,
    totalSuccess: totalSuccess,
    totalFailed: totalFailed,
    successRate: totalSent > 0 ? 
      ((totalSuccess / totalSent) * 100).toFixed(1) 
      : (totalSuccess > 0 ? '100.0' : '0.0')
  };
  
  return {
    stats,
    logs: uniqueSMSLogs,
    hourlyDistribution,
    approvalTypes: approvalTypes // ✅ Tüm kategorileri göster (value 0 olanlar dahil)
  };
}

function generateTrendData(logs) {
  const last7Days = [];
  for (let i = 6; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    const dateStr = date.toISOString().split('T')[0];
    
    const dayLogs = logs.filter(log => log.timestamp && log.timestamp.startsWith(dateStr));
    
    last7Days.push({
      date: dateStr,
      total: dayLogs.length,
      success: dayLogs.filter(l => l.level === 'SUCCESS').length,
      errors: dayLogs.filter(l => l.level === 'ERROR').length,
      activeTablets: new Set(dayLogs.filter(log => log.store_code !== 'UNKNOWN').map(log => log.device_id)).size
    });
  }
  
  return last7Days;
}

// 📊 TREND CALCULATION FUNCTIONS (Mock data yerine gerçek hesaplamalar)
function calculateActiveTabletsChange(trendData) {
  if (trendData.length < 2) return 0;
  
  const today = trendData[trendData.length - 1];
  const yesterday = trendData[trendData.length - 2];
  
  if (yesterday.activeTablets === 0) return today.activeTablets > 0 ? 100 : 0;
  
  const change = ((today.activeTablets - yesterday.activeTablets) / yesterday.activeTablets) * 100;
  return parseFloat(change.toFixed(1));
}

function calculateTodayLogsChange(trendData) {
  if (trendData.length < 2) return 0;
  
  const today = trendData[trendData.length - 1];
  const yesterday = trendData[trendData.length - 2];
  
  if (yesterday.total === 0) return today.total > 0 ? 100 : 0;
  
  const change = ((today.total - yesterday.total) / yesterday.total) * 100;
  return parseFloat(change.toFixed(1));
}

function calculateSuccessRateChange(trendData) {
  if (trendData.length < 2) return 0;
  
  const today = trendData[trendData.length - 1];
  const yesterday = trendData[trendData.length - 2];
  
  const todaySuccessRate = today.total > 0 ? (today.success / today.total) * 100 : 0;
  const yesterdaySuccessRate = yesterday.total > 0 ? (yesterday.success / yesterday.total) * 100 : 0;
  
  const change = todaySuccessRate - yesterdaySuccessRate;
  return parseFloat(change.toFixed(1));
}

// 🚫 RED SEBEPLERI ANALİZİ
function generateRejectionReasonsAnalysis(errorLogs) {
  const rejectionMap = {};
  
  debugLog(`🚫 Rejection analysis: Processing ${errorLogs.length} error logs`);
  debugLog(`🚫 Error logs categories:`, errorLogs.map(log => ({ category: log.category, level: log.level, message: log.message })));
  
  errorLogs.forEach(log => {
    // ✅ DÜZELTME: Müşteri kayıt hatalarını ve ilgili hataları kontrol et
    if (log.category !== 'CUSTOMER_CREATE' && 
        log.category !== 'CUSTOMER_VALIDATION' && 
        log.category !== 'CUSTOMER_CHECK' &&
        !log.message?.toLowerCase().includes('account already exists') &&
        !log.message?.toLowerCase().includes('customer creation failed')) {
      debugLog(`🚫 Skipping irrelevant log: ${log.category} - ${log.message}`);
      return;
    }
    
    // ✅ DÜZELTME: Hata kodunu belirle - önce data'daki rejection_code'u kontrol et
    let rejectionCode = log.data?.rejection_code || log.data?.rejectionCode || 'UNKNOWN';
    let rejectionReason = log.data?.rejection_reason || log.data?.rejectionReason || log.message;
    
    // ✅ DÜZELTME: Eğer data'da rejection_code varsa, onu kullan ve diğer kontrolleri atla
    if (rejectionCode !== 'UNKNOWN') {
      // Data'dan gelen kodu kullan, ek kontrollere gerek yok
    }
    // ✅ DÜZELTME: errorMessage'dan hata kodunu çıkar
    else if (log.data?.errorMessage) {
      const errorMessage = log.data.errorMessage;
      
      // API hatalarını kategorize et - Eski R formatında kodlar
      if (errorMessage.includes('String was not recognized as a valid Boolean')) {
        rejectionCode = 'R020';
        rejectionReason = 'API Veri Tipi Hatası: Boolean değeri geçersiz';
      } else if (errorMessage.includes('API Hatası')) {
        rejectionCode = 'R021';
        rejectionReason = 'Genel API Hatası';
      } else if (errorMessage.includes('network') || errorMessage.includes('connection')) {
        rejectionCode = 'R022';
        rejectionReason = 'API Bağlantı Hatası';
      } else if (errorMessage.includes('timeout')) {
        rejectionCode = 'R023';
        rejectionReason = 'API Zaman Aşımı Hatası';
      } else if (errorMessage.includes('unauthorized') || errorMessage.includes('401')) {
        rejectionCode = 'R024';
        rejectionReason = 'API Yetkilendirme Hatası';
      } else if (errorMessage.includes('not found') || errorMessage.includes('404')) {
        rejectionCode = 'R025';
        rejectionReason = 'API Endpoint Bulunamadı';
      } else if (errorMessage.includes('server error') || errorMessage.includes('500')) {
        rejectionCode = 'R026';
        rejectionReason = 'API Sunucu Hatası';
      } else {
        rejectionCode = 'R027';
        rejectionReason = 'Bilinmeyen API Hatası';
      }
    }
    // ✅ DÜZELTME: Message'dan hata tipini belirle
    else if (log.message) {
      const message = log.message.toLowerCase();
      
      // ✅ DÜZELTME: "Customer creation failed" genel bir mesaj, 
      // eğer errorMessage varsa onu kullan, yoksa genel hata kodu ata
      if (message.includes('creation failed')) {
        if (log.data?.errorMessage) {
          // errorMessage varsa, onu tekrar kontrol et
          const errorMessage = log.data.errorMessage;
          
          if (errorMessage.includes('String was not recognized as a valid Boolean')) {
            rejectionCode = 'R020';
            rejectionReason = 'API Veri Tipi Hatası: Boolean değeri geçersiz';
          } else if (errorMessage.includes('String was not recognized as a valid DateTime')) {
            rejectionCode = 'R020';
            rejectionReason = 'API Veri Tipi Hatası: Tarih formatı geçersiz';
          } else if (errorMessage.includes('Input string was not in a correct format')) {
            rejectionCode = 'R020';
            rejectionReason = 'API Veri Tipi Hatası: Veri formatı geçersiz';
          } else {
            rejectionCode = 'R029';
            rejectionReason = 'Müşteri Oluşturma Başarısız';
          }
        } else {
          rejectionCode = 'R029';
          rejectionReason = 'Müşteri Oluşturma Başarısız';
        }
      } else if (message.includes('invalid response')) {
        rejectionCode = 'R028';
        rejectionReason = 'API Geçersiz Yanıt Hatası';
      } else if (message.includes('timeout')) {
        rejectionCode = 'R023';
        rejectionReason = 'API Zaman Aşımı Hatası';
      } else if (message.includes('network')) {
        rejectionCode = 'R022';
        rejectionReason = 'API Bağlantı Hatası';
      } else if (message.includes('unauthorized')) {
        rejectionCode = 'R024';
        rejectionReason = 'API Yetkilendirme Hatası';
      } else if (message.includes('not found')) {
        rejectionCode = 'R025';
        rejectionReason = 'API Endpoint Bulunamadı';
      } else if (message.includes('server error')) {
        rejectionCode = 'R026';
        rejectionReason = 'API Sunucu Hatası';
      } else {
        rejectionCode = 'R027';
        rejectionReason = 'Bilinmeyen API Hatası: ' + log.message;
      }
    }
    
    if (!rejectionMap[rejectionCode]) {
      rejectionMap[rejectionCode] = {
        rejectionCode,
        reasonMapping: getRejectionReasonMapping(rejectionCode, rejectionReason),
        count: 0,
        stores: new Set(),
        employees: new Set(),
        details: []
      };
    }
    
    const rejection = rejectionMap[rejectionCode];
    rejection.count++;
    
    // Store bilgisi ekle
    if (log.store_code && log.store_code !== 'UNKNOWN') {
      const storeInfo = `${log.store_code} - ${storeNames[log.store_code] || log.store_code}`;
      rejection.stores.add(storeInfo);
    }
    
    // Plasiyer bilgisi ekle
    const employeeName = log.plasiyer_name || log.data?.plasiyer_name || log.data?.employeeName || '';
    const employeeCode = log.data?.employeeCode || log.data?.plasiyer_code || log.data?.employeeId || '';
    if (employeeName && employeeName !== 'Belirtilmemiş') {
      rejection.employees.add(employeeName);
    }
    
    // Detay bilgi ekle
    rejection.details.push({
      timestamp: log.timestamp,
      storeCode: log.store_code,
      storeName: storeNames[log.store_code] || log.store_code,
      employeeName: employeeName,
      employeeCode: employeeCode,
      customerName: getCustomerNameFromLog(log),
      message: log.message,
      errorMessage: log.data?.errorMessage || 'Belirtilmemiş',
      // ✅ DÜZELTME: Kod kısmında açıklama yerine kod göster
      code: rejectionCode,
      reason: getRejectionReasonMapping(rejectionCode, rejectionReason),
      // ✅ TC numarası ekle
      tcNumber: log.data?.tcNumber || log.data?.tc || log.data?.requestData?.tcNumber || ''
    });
  });
  
  // Array'e çevir ve sırala
  const rejectionReasons = Object.values(rejectionMap).map(reason => ({
    ...reason,
    stores: Array.from(reason.stores),
    employees: Array.from(reason.employees),
    // ✅ DÜZELTME: Kod kısmında sadece kod göster, açıklama değil
    code: reason.rejectionCode,
    reason: reason.reasonMapping
  })).sort((a, b) => b.count - a.count);
  
  debugLog(`🚫 Rejection reasons analysis: ${rejectionReasons.length} unique codes`);
  
  return rejectionReasons;
}

// Red sebep kodlarını Türkçe açıklamalara çevir
function getRejectionReasonMapping(code, originalReason) {
  const mappings = {
    'R001': 'Geçersiz Email Formatı',
    'R002': 'Adres Detayı Eksik',
    'R003': 'Şehir Seçilmemiş',
    'R004': 'İlçe Seçilmemiş',
    'R005': 'Telefon Başka TC\'ye Kayıtlı',
    'R006': 'Telefon Doğrulama Beklemede',
    'R007': 'Geçersiz Birincil Telefon',
    'R008': 'İkinci Telefon Zorunlu',
    'R009': 'Aynı Telefon Numaraları',
    'R010': 'SMS Doğrulama API Hatası',
    'R011': 'Yanlış SMS Kodu',
    'R012': 'İkinci Telefon SMS Kodu Eksik',
    'R013': 'İkinci Telefon SMS API Hatası',
    'R014': 'İkinci Telefon Yanlış SMS Kodu',
    'R015': 'Müşteri Hesabı Zaten Var',
    'R016': 'Limit Kısıtlaması Mevcut',
    'R017': 'Akrabası İcrada',
    'R018': 'Bilinmeyen HesapAçılabilir Durumu',
    'R019': 'Müşteri Kontrol API Hatası',
    // ✅ YENİ API HATA KODLARI (R formatında)
    'R020': 'API Veri Tipi Hatası: Boolean değeri geçersiz',
    'R021': 'Genel API Hatası',
    'R022': 'API Bağlantı Hatası',
    'R023': 'API Zaman Aşımı Hatası',
    'R024': 'API Yetkilendirme Hatası',
    'R025': 'API Endpoint Bulunamadı',
    'R026': 'API Sunucu Hatası',
    'R027': 'Bilinmeyen API Hatası',
    'R028': 'API Geçersiz Yanıt Hatası',
    'R029': 'Müşteri Oluşturma Başarısız',
    'UNKNOWN': 'Belirtilmemiş Hata'
  };
  
  return mappings[code] || originalReason || 'Bilinmeyen Hata';
}

// 📱 SMS HATA ANALİZİ
function generateSMSErrorAnalysis(allLogs) {
  // SMS ile ilgili hataları ve telefon doğrulama hatalarını filtrele
  const smsErrorLogs = allLogs.filter(log => 
    ((log.category === 'SMS_APPROVAL' || log.category === 'SMS_NOTIFICATION' || log.category === 'SMS_VERIFICATION_DATA') && log.level === 'ERROR') ||
    // Telefon doğrulama hatalarını da dahil et (SMS süreciyle bağlantılı)
    (log.category === 'CUSTOMER_CREATE' && log.level === 'ERROR' && 
     (log.message?.toLowerCase().includes('phone') || 
      log.message?.toLowerCase().includes('telefon') ||
      log.data?.rejectionCode?.includes('R005') || // Telefon başka TC'ye kayıtlı
      log.data?.rejectionCode?.includes('R007') || // Geçersiz birincil telefon
      log.data?.rejectionCode?.includes('R009'))) ||   // Aynı telefon numaraları
    // ✅ Telefon doğrulama API uyarılarını da dahil et (INFO/WARNING seviyesinde)
    (log.category === 'VALIDATION' && 
     (log.level === 'INFO' || log.level === 'WARNING') &&
     (log.message?.toLowerCase().includes('phone validation api warning') ||
      log.message?.toLowerCase().includes('telefon numarası kontrolü') ||
      log.data?.resultCode === -1 || // API hata kodu
      log.data?.resultCode === -2 ||
      log.data?.resultCode === -3 ||
      log.data?.status === 'API_WARNING_BUT_ALLOWED'))
  );
  
  const smsIssueMap = {};
  
  smsErrorLogs.forEach(log => {
    // SMS hatalarını kategorize et
    let issueCategory = 'SMS_UNKNOWN_ERROR';
    let issueTitle = 'Bilinmeyen SMS Hatası';
    let issueCode = 'SMS_E000';
    
    const message = log.message?.toLowerCase() || '';
    const errorData = log.data?.errorMessage?.toLowerCase() || '';
    const errorCode = log.data?.errorCode;
    
    // Hata tipini belirle
    if (message.includes('sms send failed') || message.includes('sms gönderme hatası') || message.includes('SMS gönderme başarısız')) {
      if (message.includes('empty phone number') || errorData.includes('phone')) {
        issueCategory = 'PHONE_NUMBER_ERROR';
        issueTitle = 'Telefon Numarası Hatası';
        issueCode = 'SMS_E001';
      } else if (errorCode === 401 || errorData.includes('unauthorized')) {
        issueCategory = 'SMS_AUTH_ERROR';
        issueTitle = 'SMS Servis Yetkilendirme Hatası';
        issueCode = 'SMS_E002';
      } else if (errorCode === 429 || errorData.includes('limit')) {
        issueCategory = 'SMS_RATE_LIMIT';
        issueTitle = 'SMS Gönderim Limit Aşımı';
        issueCode = 'SMS_E003';
      } else if (errorCode >= 500 || errorData.includes('server')) {
        issueCategory = 'SMS_SERVER_ERROR';
        issueTitle = 'SMS Servis Sunucu Hatası';
        issueCode = 'SMS_E004';
      } else {
        issueCategory = 'SMS_SEND_GENERAL';
        issueTitle = 'SMS Gönderim Hatası';
        issueCode = 'SMS_E005';
      }
    } else if (message.includes('phone already') || message.includes('telefon başka') || 
               message.includes('başka tc') || message.includes('already registered') ||
               errorData.includes('already used') || errorData.includes('başka tc') ||
               log.data?.rejectionCode === 'R005' || // Telefon başka TC'ye kayıtlı
               message.includes('phone already registered')) {
      issueCategory = 'PHONE_TC_CONFLICT';
      issueTitle = 'Telefon Başka TC\'ye Kayıtlı';
      issueCode = 'SMS_E012';
    } else if (message.includes('geçersiz birincil telefon') || message.includes('invalid primary phone') ||
               log.data?.rejectionCode === 'R007') {
      issueCategory = 'INVALID_PHONE_FORMAT';
      issueTitle = 'Geçersiz Telefon Formatı';
      issueCode = 'SMS_E013';
    } else if (message.includes('aynı telefon') || message.includes('duplicate phone') ||
               log.data?.rejectionCode === 'R009') {
      issueCategory = 'DUPLICATE_PHONE_NUMBERS';
      issueTitle = 'Tekrar Eden Telefon Numaraları';
      issueCode = 'SMS_E014';
    } else if (message.includes('phone validation api warning') || 
               message.includes('telefon numarası kontrolü') ||
               log.data?.resultCode === -1 || 
               log.data?.resultCode === -2 || 
               log.data?.resultCode === -3 ||
               log.data?.status === 'API_WARNING_BUT_ALLOWED') {
      // API uyarı türünü belirle
      if (log.data?.resultCode === -1) {
        issueCategory = 'PHONE_API_UNAVAILABLE';
        issueTitle = 'Telefon Doğrulama API Kullanılamıyor';
        issueCode = 'SMS_E015';
      } else if (log.data?.resultCode === -2) {
        issueCategory = 'PHONE_API_ERROR';
        issueTitle = 'Telefon Doğrulama API Geçici Hatası';
        issueCode = 'SMS_E016';
      } else if (log.data?.resultCode === -3) {
        issueCategory = 'PHONE_API_NETWORK';
        issueTitle = 'Telefon Doğrulama Bağlantı Hatası';
        issueCode = 'SMS_E017';
      } else {
        issueCategory = 'PHONE_API_WARNING';
        issueTitle = 'Telefon Doğrulama API Uyarısı';
        issueCode = 'SMS_E018';
      }
    } else if (message.includes('verification failed') || message.includes('doğrulama') || 
               message.includes('Sözleşme onay SMS doğrulama başarısız') ||
               message.includes('Sözleşme onay SMS doğrulama reddedildi') ||
               message.includes('KVK izni doğrulama başarısız') ||
               message.includes('Ticari ileti onayı doğrulama başarısız') ||
               message.includes('İkinci telefon doğrulama başarısız')) {
      if (message.includes('wrong code') || message.includes('yanlış') || message.includes('reddedildi')) {
        issueCategory = 'SMS_WRONG_CODE';
        issueTitle = 'Yanlış SMS Doğrulama Kodu';
        issueCode = 'SMS_E006';
      } else if (message.includes('expired') || message.includes('süresi')) {
        issueCategory = 'SMS_CODE_EXPIRED';
        issueTitle = 'SMS Kodu Süresi Dolmuş';
        issueCode = 'SMS_E007';
      } else {
        issueCategory = 'SMS_VERIFICATION_ERROR';
        issueTitle = 'SMS Doğrulama Hatası';
        issueCode = 'SMS_E008';
      }
    } else if (message.includes('customer account sms failed')) {
      issueCategory = 'ACCOUNT_SMS_ERROR';
      issueTitle = 'Hesap Bildirimi SMS Hatası';
      issueCode = 'SMS_E009';
    } else if (errorCode && (errorCode >= 400 && errorCode < 500)) {
      issueCategory = 'SMS_CLIENT_ERROR';
      issueTitle = 'SMS API İstek Hatası';
      issueCode = 'SMS_E010';
    } else if (errorData.includes('network') || errorData.includes('timeout')) {
      issueCategory = 'SMS_NETWORK_ERROR';
      issueTitle = 'SMS Ağ Bağlantı Hatası';
      issueCode = 'SMS_E011';
    }
    
    if (!smsIssueMap[issueCategory]) {
      smsIssueMap[issueCategory] = {
        issueCode,
        issueCategory,
        issueTitle,
        count: 0,
        stores: new Set(),
        phones: new Set(),
        details: []
      };
    }
    
    const issue = smsIssueMap[issueCategory];
    issue.count++;
    
    // Store bilgisi ekle
    if (log.store_code && log.store_code !== 'UNKNOWN') {
      const storeInfo = `${log.store_code} - ${storeNames[log.store_code] || log.store_code}`;
      issue.stores.add(storeInfo);
    }
    
    // Telefon numarası ekle (maskelenmiş)
    const phoneNumber = log.data?.phoneNumber || 'Bilinmiyor';
    issue.phones.add(phoneNumber);
    
    // Detay bilgi ekle
    issue.details.push({
      timestamp: log.timestamp,
      storeCode: log.store_code,
      storeName: storeNames[log.store_code] || log.store_code,
      message: log.message,
      phoneNumber: phoneNumber,
      errorCode: log.data?.errorCode,
      errorMessage: log.data?.errorMessage,
      approvalStep: log.data?.approvalStep || log.data?.type || 'unknown'
    });
  });
  
  // Array'e çevir ve sırala
  const smsIssues = Object.values(smsIssueMap).map(issue => ({
    ...issue,
    stores: Array.from(issue.stores),
    phones: Array.from(issue.phones)
  })).sort((a, b) => b.count - a.count);
  
  debugLog(`�� SMS Error analysis: ${smsIssues.length} unique issue types`);
  
  return smsIssues;
}

// Log'dan müşteri adını çıkar
function getCustomerNameFromLog(log) {
  const data = log.data || {};
  
  debugLog(`🔍 getCustomerNameFromLog - log data:`, {
    message: log.message,
    data: data,
    requestData: data.requestData
  });
  
  // ✅ DÜZELTME: requestData'dan müşteri adını çıkar
  if (data.requestData?.customerName) {
    debugLog(`🔍 Found customerName in requestData: ${data.requestData.customerName}`);
    return data.requestData.customerName;
  }
  
  if (data.requestData?.name && data.requestData?.surname) {
    const fullName = `${data.requestData.name} ${data.requestData.surname}`;
    debugLog(`🔍 Found name+surname in requestData: ${fullName}`);
    return fullName;
  }
  
  if (data.name && data.surname) {
    const fullName = `${data.name} ${data.surname}`;
    debugLog(`🔍 Found name+surname in data: ${fullName}`);
    return fullName;
  }
  
  if (data.customerName) {
    debugLog(`🔍 Found customerName in data: ${data.customerName}`);
    return data.customerName;
  }
  
  // Message'dan isim çıkarmaya çalış
  const nameMatch = log.message.match(/name:\s*([^,]+)/i);
  if (nameMatch) {
    debugLog(`🔍 Found name in message: ${nameMatch[1].trim()}`);
    return nameMatch[1].trim();
  }
  
  // TC'den isim çıkarmaya çalış (message'da TC: 12345678901, İsim: ÜMİT ŞAHİN formatında)
  const tcNameMatch = log.message.match(/TC:\s*(\d+),\s*İsim:\s*([^,]+)/i);
  if (tcNameMatch) {
    debugLog(`🔍 Found name in TC format: ${tcNameMatch[2].trim()}`);
    return tcNameMatch[2].trim();
  }
  
  debugLog(`🔍 No customer name found, returning 'Bilinmiyor'`);
  return 'Bilinmiyor';
}

// 📊 MÜŞTERI ANALİTİKLERİ
function generateCustomerAnalytics(errorLogs, successLogs, scope = 'daily') {
  const storeMap = {};
  
  // Hem başarılı hem başarısız işlemleri analiz et
  [...errorLogs, ...successLogs].forEach(log => {
    if (log.category !== 'CUSTOMER_CREATE') return;
    if (!log.store_code || log.store_code === 'UNKNOWN') return;
    
    const storeCode = log.store_code;
    
    if (!storeMap[storeCode]) {
      storeMap[storeCode] = {
        storeCode,
        storeName: storeNames[storeCode] || storeCode,
        totalAttempts: 0,
        successfulRegistrations: 0,
        failedRegistrations: 0,
        successRate: 0,
        employees: new Set()
      };
    }
    
    const store = storeMap[storeCode];
    
    // ✅ DÜZELTME: Sadece gerçek denemeleri say, başarılı süreçleri sayma
    const isRealAttempt = (log) => {
      // Başarısız işlemler her zaman deneme
      if (log.level === 'ERROR') return true;
      
      // Başarılı işlemlerden sadece gerçek müşteri oluşturma deneme sayılır
      if (log.level === 'SUCCESS' && log.message === 'Customer account created successfully') {
        return true;
      }
      
      // Başarılı süreçler (eligibility check, TC check vb.) deneme sayılmaz
      const successfulProcesses = [
        'Customer eligibility check passed',
        'Check TC by Phone completed successfully',
        'Upload Documents completed successfully',
        'SMS verification successful',
        'Verification code sent successfully'
      ];
      
      return !successfulProcesses.some(process => log.message.includes(process));
    };
    
    // Sadece gerçek denemeleri say
    if (isRealAttempt(log)) {
      store.totalAttempts++;
    }
    
    if (log.level === 'ERROR') {
      store.failedRegistrations++;
    } else if (log.level === 'SUCCESS' && (
      log.message === 'Customer account created successfully' ||
      log.message === 'Customer created successfully'
    )) {
      // ✅ Hem eski hem yeni format müşteri hesabı oluşturma başarılarını say
      store.successfulRegistrations++;
    }
    
    // Plasiyer bilgisi ekle
    if (log.plasiyer_name) {
      store.employees.add(log.plasiyer_name);
    }
  });
  
  // Başarı oranlarını hesapla
  const storeStats = Object.values(storeMap).map(store => ({
    ...store,
    employees: Array.from(store.employees),
    successRate: store.totalAttempts > 0 ? 
      Math.round((store.successfulRegistrations / store.totalAttempts) * 100) : 0
  }));
  
  debugLog(`📊 Customer analytics: ${storeStats.length} stores`);
  
  return {
    storeStats,
    totalStores: storeStats.length,
    scope,
    period: scope === 'daily' ? 'Günlük' : scope === 'monthly' ? 'Aylık' : 'Yıllık'
  };
}

// 📄 REPORTS ENDPOINTS
app.get('/api/reports/types', verifyToken, (req, res) => {
  try {
    const reportTypes = [
      { id: 'overview', name: 'Genel Bakış Raporu', icon: '📊', description: 'Tüm metriklerin özeti' },
      { id: 'customer', name: 'Müşteri Analizi', icon: '👥', description: 'Müşteri davranışları ve trendler' },
      { id: 'sms', name: 'SMS Performans', icon: '📱', description: 'SMS gönderim istatistikleri' },
      { id: 'errors', name: 'Hata Analizi', icon: '⚠️', description: 'Sistem hataları ve çözümler' },
      { id: 'stores', name: 'Mağaza Performansı', icon: '🏪', description: 'Mağaza bazlı metrikler' }
    ];
    
    res.json({ success: true, data: reportTypes });
  } catch (error) {
    debugLog('❌ Reports types error:', error);
    res.status(500).json({ success: false, error: 'Rapor türleri alınamadı' });
  }
});

app.post('/api/reports/generate', verifyToken, async (req, res) => {
  try {
    const { reportType, period, dateRange } = req.body;
    
    // Tarih aralığını belirle
    let startDate, endDate;
    const today = new Date();
    
    switch (period) {
      case 'daily':
        startDate = new Date(today);
        endDate = new Date(today);
        break;
      case 'weekly':
        startDate = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
        endDate = new Date(today);
        break;
      case 'monthly':
        startDate = new Date(Date.UTC(today.getFullYear(), today.getMonth(), 1));
        endDate = new Date(today);
        break;
      case 'yearly':
        startDate = new Date(Date.UTC(today.getFullYear(), 0, 1));
        endDate = new Date(today);
        break;
      case 'custom':
        startDate = new Date(dateRange.start);
        endDate = new Date(dateRange.end);
        break;
      default:
        startDate = new Date(today);
        endDate = new Date(today);
    }
    
    // Logları oku
    const logs = await readLogsFromHierarchicalStructure(startDate, endDate);
    
    // Rapor türüne göre veri hazırla
    let reportData = {};
    
    switch (reportType) {
      case 'overview':
        reportData = generateOverviewData(logs);
        break;
      case 'customer':
        const errorLogs = logs.filter(log => log.level === 'ERROR');
        const successLogs = logs.filter(log => log.level === 'SUCCESS');
        reportData = generateCustomerAnalytics(errorLogs, successLogs, period);
        break;
      case 'sms':
        reportData = generateSMSAnalytics(logs);
        break;
      case 'errors':
        const errors = logs.filter(log => log.level === 'ERROR');
        reportData = {
          totalErrors: errors.length,
          errorCategories: generateRejectionReasonsAnalysis(errors),
          recentErrors: getRecentErrors(logs),
          period: period
        };
        break;
      case 'stores':
        reportData = generateStoreStats(logs);
        break;
      default:
        reportData = generateOverviewData(logs);
    }
    
    // Benzersiz rapor ID'si oluştur
    const reportId = Date.now();
    
    res.json({
      success: true,
      data: {
        id: reportId,
        reportType,
        period,
        dateRange: { start: startDate.toISOString().split('T')[0], end: endDate.toISOString().split('T')[0] },
        generatedAt: new Date().toISOString(),
        reportData
      }
    });
    
  } catch (error) {
    debugLog('❌ Report generation error:', error);
    res.status(500).json({ success: false, error: 'Rapor oluşturulamadı' });
  }
});

app.get('/api/reports/recent', verifyToken, async (req, res) => {
  try {
    // Son oluşturulan raporları simüle et (gerçek uygulamada veritabanından alınır)
    const recentReports = [
      {
        id: 1,
        type: 'overview',
        name: 'Genel Bakış Raporu',
        period: 'daily',
        dateRange: { start: '2024-03-15', end: '2024-03-15' },
        createdAt: '2024-03-15T10:30:00Z',
        status: 'completed'
      },
      {
        id: 2,
        type: 'customer',
        name: 'Müşteri Analizi',
        period: 'monthly',
        dateRange: { start: '2024-03-01', end: '2024-03-15' },
        createdAt: '2024-03-14T15:45:00Z',
        status: 'completed'
      }
    ];
    
    res.json({ success: true, data: recentReports });
  } catch (error) {
    debugLog('❌ Recent reports error:', error);
    res.status(500).json({ success: false, error: 'Son raporlar alınamadı' });
  }
});

// Raporu ID ile al
app.get('/api/reports/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Raporu simüle et (gerçek uygulamada veritabanından alınır)
    const report = {
      id: parseInt(id),
      reportType: 'overview',
      name: 'Genel Bakış Raporu',
      period: 'daily',
      dateRange: { start: '2024-03-15', end: '2024-03-15' },
      generatedAt: '2024-03-15T10:30:00Z',
      status: 'completed',
      reportData: {
        totalLogs: 1250,
        successRate: 94.5,
        activeStores: 6,
        activeTablets: 12,
        errors: 68,
        smsSent: 1182
      }
    };
    
    res.json({ success: true, data: report });
  } catch (error) {
    debugLog('❌ Get report by ID error:', error);
    res.status(500).json({ success: false, error: 'Rapor alınamadı' });
  }
});

// PDF oluşturma fonksiyonu
const generatePDF = (reportData) => {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument();
      const chunks = [];
      
      doc.on('data', chunk => chunks.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      
      // PDF başlığı
      doc.fontSize(24)
         .font('Helvetica-Bold')
         .text('YeniKoza Dashboard Report', { align: 'center' });
      
      doc.moveDown();
      
      // Rapor bilgileri
      doc.fontSize(16)
         .font('Helvetica-Bold')
         .text(reportData.name);
      
      doc.fontSize(12)
         .font('Helvetica')
         .text(`Report ID: ${reportData.id}`)
         .text(`Period: ${reportData.period}`)
         .text(`Date Range: ${reportData.dateRange.start} - ${reportData.dateRange.end}`)
         .text(`Generated: ${new Date(reportData.generatedAt).toLocaleDateString('en-US')}`);
      
      doc.moveDown();
      
      // Metrikler
      doc.fontSize(14)
         .font('Helvetica-Bold')
         .text('System Metrics');
      
      doc.fontSize(12)
         .font('Helvetica')
         .text(`Total Logs: ${reportData.data.totalLogs}`)
         .text(`Success Rate: %${reportData.data.successRate}`)
         .text(`Active Stores: ${reportData.data.activeStores}`)
         .text(`Active Tablets: ${reportData.data.activeTablets}`)
         .text(`Error Count: ${reportData.data.errors}`)
         .text(`SMS Sent: ${reportData.data.smsSent}`);
      
      doc.moveDown();
      
      // Alt bilgi
      doc.fontSize(10)
         .font('Helvetica-Oblique')
         .text('This report was automatically generated by YeniKoza Dashboard system.', { align: 'center' });
      
      doc.end();
    } catch (error) {
      reject(error);
    }
  });
};

// Excel oluşturma fonksiyonu
const generateExcel = (reportData) => {
  return new Promise(async (resolve, reject) => {
    try {
      const workbook = new ExcelJS.Workbook();
      const worksheet = workbook.addWorksheet('Report');
      
      // Başlık
      worksheet.mergeCells('A1:D1');
      worksheet.getCell('A1').value = 'YeniKoza Dashboard Report';
      worksheet.getCell('A1').font = { bold: true, size: 16 };
      worksheet.getCell('A1').alignment = { horizontal: 'center' };
      
      // Rapor bilgileri
      worksheet.getCell('A3').value = 'Report ID:';
      worksheet.getCell('B3').value = reportData.id;
      worksheet.getCell('A4').value = 'Period:';
      worksheet.getCell('B4').value = reportData.period;
      worksheet.getCell('A5').value = 'Date Range:';
      worksheet.getCell('B5').value = `${reportData.dateRange.start} - ${reportData.dateRange.end}`;
      worksheet.getCell('A6').value = 'Generated:';
      worksheet.getCell('B6').value = new Date(reportData.generatedAt).toLocaleDateString('en-US');
      
      // Metrikler başlığı
      worksheet.getCell('A8').value = 'System Metrics';
      worksheet.getCell('A8').font = { bold: true, size: 14 };
      
      // Metrikler
      const metrics = [
        ['Total Logs', reportData.data.totalLogs || 0],
        ['Success Rate', `${reportData.data.successRate || 0}%`],
        ['Active Stores', reportData.data.activeStores || 0],
        ['Active Tablets', reportData.data.activeTablets || 0],
        ['Error Count', reportData.data.errors || 0],
        ['SMS Sent', reportData.data.smsSent || 0]
      ];
      
      metrics.forEach((metric, index) => {
        worksheet.getCell(`A${10 + index}`).value = metric[0];
        worksheet.getCell(`B${10 + index}`).value = metric[1];
      });
      
      // Sütun genişliklerini ayarla
      worksheet.getColumn('A').width = 15;
      worksheet.getColumn('B').width = 20;
      
      // Buffer olarak döndür
      const buffer = await workbook.xlsx.writeBuffer();
      resolve(buffer);
    } catch (error) {
      reject(error);
    }
  });
};

// Raporu indir
app.get('/api/reports/:id/download', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { format = 'pdf' } = req.query;
    
    // Rapor verilerini simüle et
    const reportData = {
      id: parseInt(id),
      reportType: 'overview',
      name: 'Genel Bakış Raporu',
      period: 'daily',
      dateRange: { start: '2024-03-15', end: '2024-03-15' },
      generatedAt: '2024-03-15T10:30:00Z',
      data: {
        totalLogs: 1250,
        successRate: 94.5,
        activeStores: 6,
        activeTablets: 12,
        errors: 68,
        smsSent: 1182
      }
    };
    
    if (format === 'pdf') {
      // Gerçek PDF oluştur
      const pdfBuffer = await generatePDF(reportData);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="yenikoza-rapor-${id}.pdf"`);
      res.send(pdfBuffer);
    } else if (format === 'excel') {
      // Gerçek Excel oluştur
      const excelBuffer = await generateExcel(reportData);
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="yenikoza-rapor-${id}.xlsx"`);
      res.send(excelBuffer);
    } else {
      res.status(400).json({ success: false, error: 'Geçersiz format' });
    }
  } catch (error) {
    debugLog('❌ Download report error:', error);
    res.status(500).json({ success: false, error: 'Rapor indirilemedi' });
  }
});

// ⚙️ SETTINGS ENDPOINTS
app.get('/api/settings/profile', verifyToken, async (req, res) => {
  try {
    const users = await loadUsers();
    const user = users.find(u => u.username === req.user.username);
    
    if (!user) {
      return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı' });
    }
    
    const profile = {
      name: user.name || user.username,
      email: user.email || `${user.username}@yenikoza.com`,
      role: user.role || 'Administrator',
      phone: user.phone || '+90 555 123 4567',
      avatar: user.avatar || '👤'
    };
    
    res.json({ success: true, data: profile });
  } catch (error) {
    debugLog('❌ Profile settings error:', error);
    res.status(500).json({ success: false, error: 'Profil bilgileri alınamadı' });
  }
});

app.put('/api/settings/profile', verifyToken, async (req, res) => {
  try {
    const { name, email, phone, role } = req.body;
    const users = await loadUsers();
    const userIndex = users.findIndex(u => u.username === req.user.username);
    
    if (userIndex === -1) {
      return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı' });
    }
    
    // Profil bilgilerini güncelle
    users[userIndex] = {
      ...users[userIndex],
      name: name || users[userIndex].name,
      email: email || users[userIndex].email,
      phone: phone || users[userIndex].phone,
      role: role || users[userIndex].role
    };
    
    await saveUsers(users);
    
    res.json({ success: true, message: 'Profil başarıyla güncellendi' });
  } catch (error) {
    debugLog('❌ Profile update error:', error);
    res.status(500).json({ success: false, error: 'Profil güncellenemedi' });
  }
});

app.get('/api/settings/notifications', verifyToken, async (req, res) => {
  try {
    // Kullanıcının bildirim ayarlarını al (gerçek uygulamada veritabanından)
    const notifications = {
      emailNotifications: true,
      smsNotifications: false,
      errorAlerts: true,
      performanceAlerts: true,
      dailyReports: false,
      weeklyReports: true
    };
    
    res.json({ success: true, data: notifications });
  } catch (error) {
    debugLog('❌ Notification settings error:', error);
    res.status(500).json({ success: false, error: 'Bildirim ayarları alınamadı' });
  }
});

app.put('/api/settings/notifications', verifyToken, async (req, res) => {
  try {
    const notificationSettings = req.body;
    
    // Bildirim ayarlarını kaydet (gerçek uygulamada veritabanına)
    debugLog('📧 Notification settings updated:', notificationSettings);
    
    res.json({ success: true, message: 'Bildirim ayarları güncellendi' });
  } catch (error) {
    debugLog('❌ Notification update error:', error);
    res.status(500).json({ success: false, error: 'Bildirim ayarları güncellenemedi' });
  }
});

app.get('/api/settings/dashboard', verifyToken, async (req, res) => {
  try {
    // Dashboard ayarlarını al (gerçek uygulamada veritabanından)
    const dashboardSettings = {
      defaultView: 'overview',
      autoRefresh: true,
      refreshInterval: 30,
      showTrends: true,
      compactMode: false,
      darkMode: false
    };
    
    res.json({ success: true, data: dashboardSettings });
  } catch (error) {
    debugLog('❌ Dashboard settings error:', error);
    res.status(500).json({ success: false, error: 'Dashboard ayarları alınamadı' });
  }
});

app.put('/api/settings/dashboard', verifyToken, async (req, res) => {
  try {
    const dashboardSettings = req.body;
    
    // Dashboard ayarlarını kaydet (gerçek uygulamada veritabanına)
    debugLog('📊 Dashboard settings updated:', dashboardSettings);
    
    res.json({ success: true, message: 'Dashboard ayarları güncellendi' });
  } catch (error) {
    debugLog('❌ Dashboard update error:', error);
    res.status(500).json({ success: false, error: 'Dashboard ayarları güncellenemedi' });
  }
});

app.get('/api/settings/api-keys', verifyToken, async (req, res) => {
  try {
    // API anahtarlarını al (gerçek uygulamada veritabanından)
    const apiKeys = [
      { id: 1, name: 'Dashboard API', key: 'dk_1234567890abcdef', created: '2024-01-15', lastUsed: '2024-03-15' },
      { id: 2, name: 'SMS Service API', key: 'sms_abcdef1234567890', created: '2024-02-01', lastUsed: '2024-03-14' }
    ];
    
    res.json({ success: true, data: apiKeys });
  } catch (error) {
    debugLog('❌ API keys error:', error);
    res.status(500).json({ success: false, error: 'API anahtarları alınamadı' });
  }
});

app.post('/api/settings/api-keys', verifyToken, async (req, res) => {
  try {
    const { name } = req.body;
    
    // Yeni API anahtarı oluştur
    const newKey = {
      id: Date.now(),
      name: name || `API Key ${Date.now()}`,
      key: `key_${Math.random().toString(36).substr(2, 15)}`,
      created: new Date().toISOString().split('T')[0],
      lastUsed: 'Never'
    };
    
    // API anahtarını kaydet (gerçek uygulamada veritabanına)
    debugLog('🔑 New API key created:', newKey);
    
    res.json({ success: true, data: newKey });
  } catch (error) {
    debugLog('❌ API key creation error:', error);
    res.status(500).json({ success: false, error: 'API anahtarı oluşturulamadı' });
  }
});

app.delete('/api/settings/api-keys/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // API anahtarını sil (gerçek uygulamada veritabanından)
    debugLog('🗑️ API key deleted:', id);
    
    res.json({ success: true, message: 'API anahtarı silindi' });
  } catch (error) {
    debugLog('❌ API key deletion error:', error);
    res.status(500).json({ success: false, error: 'API anahtarı silinemedi' });
  }
});

// Initialize and start server
const PORT = process.env.PORT || 3002;

app.listen(PORT, '0.0.0.0', async () => {
  await ensureLogsDir();
  debugLog('');
  debugLog('🚀 ====== YeniKoza Logging Service ======');
  debugLog(`📡 Server running on http://localhost:${PORT}`);
  debugLog(`📁 Logs directory: ${LOGS_DIR}`);
  debugLog('📋 Available endpoints:');
  debugLog('   🔐 Authentication:');
  debugLog('      POST /api/auth/login     - User login');
  debugLog('      GET  /api/auth/me        - Get current user');
  debugLog('      POST /api/auth/logout    - User logout');
  debugLog('   📊 Dashboard:');
  debugLog('      POST /api/tablet-logs    - Receive logs from tablets');
  debugLog('      GET  /api/dashboard/data - Get dashboard data');
  debugLog('      GET  /api/logs/export    - Export logs');
  debugLog('      GET  /api/dashboard/sms-logs - Get SMS logs');
  debugLog('      GET  /api/health         - Health check');
  debugLog('   📄 Reports:');
  debugLog('      GET  /api/reports/types  - Get report types');
  debugLog('      POST /api/reports/generate - Generate report');
  debugLog('      GET  /api/reports/recent - Get recent reports');
  debugLog('   ⚙️ Settings:');
  debugLog('      GET  /api/settings/profile - Get user profile');
  debugLog('      PUT  /api/settings/profile - Update user profile');
  debugLog('      GET  /api/settings/notifications - Get notification settings');
  debugLog('      PUT  /api/settings/notifications - Update notification settings');
  debugLog('      GET  /api/settings/dashboard - Get dashboard settings');
  debugLog('      PUT  /api/settings/dashboard - Update dashboard settings');
  debugLog('      GET  /api/settings/api-keys - Get API keys');
  debugLog('      POST /api/settings/api-keys - Create API key');
  debugLog('      DELETE /api/settings/api-keys/:id - Delete API key');
  debugLog('==========================================');
  debugLog('');
}); 