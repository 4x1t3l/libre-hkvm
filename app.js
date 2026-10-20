const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const net = require('net');
const { spawn, exec, execSync } = require('child_process');
const os = require('os');
const util = require('util');
const execPromise = util.promisify(exec);
const { Client } = require('ssh2');
require('dotenv').config();

// ============= PLATFORM DETECTION =============
const isWindows = process.platform === 'win32';
const isLinux = process.platform === 'linux';

// ============= CONSTANTS =============
const DEFAULT_SSH_PORT = 2222;

// ============= UTILITY FUNCTIONS =============

/**
 * Get validated SSH port from VM
 * Consolidates ssh_port and ssh_port_static into single value
 */
function getSSHPort(vm) {
  const port = vm.ssh_port || vm.ssh_port_static || DEFAULT_SSH_PORT;
  const portNum = parseInt(port);
  if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
    return DEFAULT_SSH_PORT;
  }
  return portNum;
}



/**
 * Log errors with VM context
 */
function logError(component, vm_id, action, error) {
  console.error(`[${component}-${vm_id}] ${action} FAILED: ${error.message}`);
  if (error.stack) {
    console.error(`[${component}-${vm_id}] Stack: ${error.stack}`);
  }
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 8080;

// For binary: use home directory or custom location for database
// __dirname will be /snapshot/hkvm (read-only in binary), so use home directory
const dbDir = process.env.HKVM_DATA_DIR || path.join(os.homedir(), '.hkvm');
const dbPath = path.join(dbDir, 'hkvm.db');

// Ensure database directory exists and is writable
try {
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true, mode: 0o755 });
    console.log('[Init] Created database directory:', dbDir);
  }
} catch (error) {
  console.error('[Init] Failed to create database directory:', dbDir, error.message);
  process.exit(1);
}

const db = new sqlite3.Database(dbPath);

const VM_DIR = path.join(os.homedir(), 'vms');
const TEMPLATES_DIR = path.join(VM_DIR, 'templates');
const ISO_DIR = path.join(VM_DIR, 'iso');
const CLOUDVM_DIR = path.join(VM_DIR, 'cloudvm');

// Create directories if they don't exist
if (!fs.existsSync(VM_DIR)) {
  fs.mkdirSync(VM_DIR, { recursive: true });
}
if (!fs.existsSync(TEMPLATES_DIR)) {
  fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
}
if (!fs.existsSync(ISO_DIR)) {
  fs.mkdirSync(ISO_DIR, { recursive: true });
}
if (!fs.existsSync(CLOUDVM_DIR)) {
  fs.mkdirSync(CLOUDVM_DIR, { recursive: true });
}

// CPU Models available
const CPU_MODELS = {
  'host': {
    name: 'Host CPU (Native)',
    description: 'Use host CPU directly - best performance',
    features: 'host'
  },
  'max': {
    name: 'Maximum Features',
    description: 'Maximum supported features by QEMU',
    features: 'max'
  },
  'qemu64': {
    name: 'QEMU 64-bit',
    description: 'Generic 64-bit processor',
    features: 'qemu64'
  },
  'kvm64': {
    name: 'KVM 64-bit',
    description: 'Optimized for KVM',
    features: 'kvm64'
  },
  'core2duo': {
    name: 'Core 2 Duo',
    description: 'Intel Core 2 Duo',
    features: 'core2duo'
  },
  'corei7': {
    name: 'Core i7',
    description: 'Intel Core i7',
    features: 'corei7'
  },
  'skylake': {
    name: 'Skylake',
    description: 'Intel Skylake',
    features: 'Skylake-Client'
  },
  'cascadelake': {
    name: 'Cascade Lake',
    description: 'Intel Cascade Lake (Server)',
    features: 'Cascadelake-Server'
  },
  'opteron': {
    name: 'Opteron',
    description: 'AMD Opteron',
    features: 'opteron'
  },
  'epyc': {
    name: 'EPYC',
    description: 'AMD EPYC (Server)',
    features: 'EPYC'
  }
};

// Machine Types available for QEMU
const MACHINE_TYPES = {
  'pc': {
    name: 'PC (i440fx - Standard)',
    description: 'Legacy PC emulation, compatible with old guests',
    arch: 'x86_64',
    features: 'Legacy BIOS, VGA, ISA/PCI buses'
  },
  'q35': {
    name: 'Q35 (ICH9 - Modern)',
    description: 'Modern chipset, recommended for newer OS',
    arch: 'x86_64',
    features: 'UEFI-ready, PCIe support, higher performance'
  },
  'microvm': {
    name: 'MicroVM (Minimal)',
    description: 'Lightweight machine type with minimal overhead',
    arch: 'x86_64',
    features: 'Fast boot, low memory footprint, optimal for containers'
  },
  'virt': {
    name: 'Virtual (ARM Generic)',
    description: 'Generic virtual platform for ARM64',
    arch: 'aarch64',
    features: 'ARM64 architecture, flexible device model'
  },
  'versatilepb': {
    name: 'Versatile Platform Baseboard (ARM)',
    description: 'ARM reference board platform',
    arch: 'arm',
    features: 'ARM 32-bit, integrator-style board'
  },
  'raspi2': {
    name: 'Raspberry Pi 2 (ARM)',
    description: 'Emulate Raspberry Pi 2 hardware',
    arch: 'arm',
    features: 'ARM-based SBC, GPIO and peripherals'
  },
  'raspi3': {
    name: 'Raspberry Pi 3 (ARM)',
    description: 'Emulate Raspberry Pi 3 hardware',
    arch: 'arm',
    features: 'ARM 64-bit, WiFi/Bluetooth simulation'
  },
  'pseries': {
    name: 'POWER Series (PowerPC)',
    description: 'IBM Power Systems emulation',
    arch: 'ppc64',
    features: 'PowerPC 64-bit, server-class machine'
  },
  's390-ccw-virtio': {
    name: 'IBM System Z (s390x)',
    description: 'IBM mainframe architecture',
    arch: 's390x',
    features: 's390x architecture, enterprise computing'
  }
};

// Network Configuration Types
const NETWORK_TYPES = {
  nat: {
    name: 'NAT (User Mode)',
    description: 'User-mode networking with automatic port forwarding',
    icon: '<svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color: #3B82F6;"><rect x="2" y="2" width="20" height="20" rx="2"/><path d="M12 2v20M2 12h20M6 6h12M6 12h12M6 18h12"/></svg>'
  },
  static_public: {
    name: 'Static Public IPv4',
    description: 'Fixed public IP with bridge network',
    icon: '<svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="color: #10B981;"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.88 20.73 6.96M12 22.08v-9.53"/></svg>'
  }
};

// DNS Providers
const DNS_PROVIDERS = [
  { name: 'Google DNS', primary: '8.8.8.8', secondary: '8.8.4.4' },
  { name: 'Cloudflare DNS', primary: '1.1.1.1', secondary: '1.0.0.1' },
  { name: 'Quad9 DNS', primary: '9.9.9.9', secondary: '149.112.112.112' },
  { name: 'OpenDNS', primary: '208.67.222.222', secondary: '208.67.220.220' },
  { name: 'Custom', primary: '', secondary: '' }
];

// SMBIOS Manufacturers
const SMBIOS_MANUFACTURERS = [
  'QEMU',
  'Proxmox',
  'Red Hat',
  'VirtualBox',
  'Microsoft Corporation',
  'Dell Inc.',
  'HP Inc.',
  'Lenovo',
  'Custom'
];

// SMBIOS Products
const SMBIOS_PRODUCTS = [
  'KVM Virtual Machine',
  'Standard PC',
  'RHEL Guest',
  'VirtualBox',
  'Virtual Machine',
  'Custom VM',
  'Cloud Instance'
];
const OS_TEMPLATES = {
  ubuntu_22_cloud: {
    name: 'Ubuntu 22.04 LTS',
    type: 'cloud-init',
    icon: 'https://i.imgur.com/wu0Ob6B.png',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    url: 'https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img',
    username: 'ubuntu',
    password: 'ubuntu'
  },
  ubuntu_24_cloud: {
    name: 'Ubuntu 24.04 LTS',
    type: 'cloud-init',
    icon: 'https://i.imgur.com/wu0Ob6B.png',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    url: 'https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img',
    username: 'ubuntu',
    password: 'ubuntu'
  },
  debian_12_cloud: {
    name: 'Debian 12',
    type: 'cloud-init',
    icon: 'https://i.imgur.com/C4SiENP.png',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    url: 'https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2',
    username: 'debian',
    password: 'debian'
  },
  fedora_40_cloud: {
    name: 'Fedora 40',
    type: 'cloud-init',
    icon: 'https://i.imgur.com/iq4y3J8.png',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    url: 'https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-40-1.14.x86_64.qcow2',
    username: 'fedora',
    password: 'fedora'
  },
  centos_9_cloud: {
    name: 'CentOS Stream 9',
    type: 'cloud-init',
    icon: 'https://i.imgur.com/MgxK5WZ.png',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    url: 'https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2',
    username: 'centos',
    password: 'centos'
  },
  almalinux_9_cloud: {
    name: 'AlmaLinux 9',
    type: 'cloud-init',
    icon: 'https://i.imgur.com/YcYGa2c.png',
    disk_size: '20G',
    memory: 2048,
    cpus: 2,
    url: 'https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2',
    username: 'almalinux',
    password: 'almalinux'
  }
};

// Middleware
app.use(express.json({ strict: false })); // Allow non-strict JSON
app.use(express.urlencoded({ extended: true }));

// Global JSON parsing error handler
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    console.warn(`[JSON Parse Error] Invalid JSON from ${req.method} ${req.path}`);
    console.warn(`  Error: ${err.message}`);
    return res.status(400).json({ error: 'Invalid JSON in request body' });
  }
  next(err);
});
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'hopingboyz-secret-key-change-in-production',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// API Key auto-detection middleware - checks for X-API-Key on every request
app.use((req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  
  if (apiKey) {
    // API key provided, validate it
    db.get(`SELECT * FROM api_keys WHERE api_key = ? AND is_active = 1`, [apiKey], (err, key) => {
      if (err) {
        console.error(`[API Auth Error] API key lookup failed:`, err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      if (!key) {
        console.warn(`[API Auth Error] Invalid or inactive API key`);
        return res.status(401).json({ error: 'Invalid API key' });
      }
      
      // Get user for the API key
      db.get(`SELECT * FROM users WHERE id = ?`, [key.user_id], (err, user) => {
        if (err || !user) {
          console.error(`[API Auth Error] User not found for API key`);
          return res.status(401).json({ error: 'User not found' });
        }
        
        // Update last used timestamp
        db.run(`UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?`, [key.id]);
        
        // Attach user and API key info to request
        req.apiKey = key;
        req.userId = key.user_id;
        req.userRole = user.role;
        req.session = req.session || {};
        req.session.userId = key.user_id;
        req.session.username = user.username;
        req.session.role = user.role;
        
        console.log(`[API Key Auth] User ${user.id} (${user.username}) authenticated via API key`);
        next();
      });
    });
  } else {
    // No API key, continue (session will handle auth)
    next();
  }
});

// Set EJS as view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// VM Process Manager (Global)
const vmProcesses = new Map();

// Initialize Database
function initializeDatabase() {
  // Enable WAL mode to reduce locking issues
  db.run('PRAGMA journal_mode = WAL', (err) => {
    if (err) console.log('[DB] Could not enable WAL mode:', err.message);
  });
  
  db.run('PRAGMA busy_timeout = 5000', (err) => {
    if (err) console.log('[DB] Could not set busy timeout:', err.message);
  });
  
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT,
      full_name TEXT,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME,
      is_active BOOLEAN DEFAULT 1
    )`);

    // Add missing columns if they don't exist
    db.all(`PRAGMA table_info(users)`, (err, columns) => {
      const columnNames = columns.map(c => c.name);
      if (!columnNames.includes('full_name')) {
        db.run(`ALTER TABLE users ADD COLUMN full_name TEXT`, (err) => {
          if (err) console.log('[DB] full_name column already exists or error:', err.message);
        });
      }
      if (!columnNames.includes('last_login')) {
        db.run(`ALTER TABLE users ADD COLUMN last_login DATETIME`, (err) => {
          if (err) console.log('[DB] last_login column already exists or error:', err.message);
        });
      }
    });

    db.run(`CREATE TABLE IF NOT EXISTS vms (
      vm_id INTEGER PRIMARY KEY AUTOINCREMENT,
      vm_name TEXT UNIQUE NOT NULL,
      os_type TEXT,
      template_type TEXT,
      hostname TEXT,
      username TEXT,
      password TEXT,
      memory INTEGER,
      cpus INTEGER,
      cpu_sockets INTEGER DEFAULT 1,
      cpu_cores INTEGER DEFAULT 2,
      cpu_threads INTEGER DEFAULT 1,
      cpu_model TEXT DEFAULT 'host',
      custom_cpu_name TEXT,
      machine_type TEXT DEFAULT 'pc',
      board_name TEXT DEFAULT 'Main-Board',
      product_name TEXT DEFAULT 'Virtual Machine',
      custom_smbios_manufacturer TEXT DEFAULT 'QEMU',
      disk_size TEXT,
      img_file TEXT,
      seed_file TEXT,
      disk_file TEXT,
      status TEXT DEFAULT 'stopped',
      uptime INTEGER DEFAULT 0,
      node_name TEXT DEFAULT 'localhost',
      smbios_manufacturer TEXT DEFAULT 'QEMU',
      smbios_product TEXT DEFAULT 'KVM Virtual Machine',
      smbios_version TEXT DEFAULT '1.0',
      smbios_serial TEXT,
      extra_args TEXT,
      enable_acpi BOOLEAN DEFAULT 1,
      enable_kvm BOOLEAN DEFAULT 1,
      network_type TEXT DEFAULT 'nat',
      ipv4_address TEXT,
      gateway TEXT,
      ipv4_gateway TEXT,
      netmask TEXT DEFAULT '24',
      ipv4_netmask TEXT DEFAULT '255.255.255.0',
      dns_servers TEXT DEFAULT '8.8.8.8,8.8.4.4',
      ssh_port INTEGER,
      ssh_port_static INTEGER DEFAULT 22,
      http_port INTEGER DEFAULT 80,
      ipv6_address TEXT,
      ipv6_gateway TEXT,
      mac_address TEXT,
      bridge_interface TEXT,
      vlan_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      owner_id INTEGER,
      FOREIGN KEY(owner_id) REFERENCES users(id)
    )`);

    // Add missing columns for existing databases (safe - ignores if already exist)
    const missingColumns = [
      { name: 'custom_cpu_name', def: 'TEXT' },
      { name: 'machine_type', def: "TEXT DEFAULT 'pc'" },
      { name: 'board_name', def: "TEXT DEFAULT 'Main-Board'" },
      { name: 'product_name', def: "TEXT DEFAULT 'Virtual Machine'" },
      { name: 'custom_smbios_manufacturer', def: "TEXT DEFAULT 'QEMU'" },
      { name: 'ipv4_netmask', def: "TEXT DEFAULT '255.255.255.0'" },
      { name: 'dns_primary', def: "TEXT DEFAULT '8.8.8.8'" },
      { name: 'dns_secondary', def: "TEXT DEFAULT '8.8.4.4'" },
      { name: 'iso_attached', def: 'TEXT' },
      { name: 'boot_from_iso', def: 'BOOLEAN DEFAULT 0' },
      { name: 'bridge_device', def: "TEXT DEFAULT 'vmbr0'" },
      { name: 'vm_disk_path', def: "TEXT" },
      { name: 'iso_path', def: "TEXT" }
    ];

    missingColumns.forEach(col => {
      db.run(`ALTER TABLE vms ADD COLUMN ${col.name} ${col.def}`, (err) => {
        if (err) {
          if (!err.message.includes('duplicate column')) {
            console.log(`Note: Column ${col.name} - ${err.message}`);
          }
        } else {
          console.log(`✓ Added column: ${col.name}`);
        }
      });
    });

    db.run(`CREATE TABLE IF NOT EXISTS vm_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vm_id INTEGER,
      action TEXT,
      status TEXT,
      message TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(vm_id) REFERENCES vms(vm_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS vm_snapshots (
      snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
      vm_id INTEGER,
      snapshot_name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      size_gb REAL,
      description TEXT,
      FOREIGN KEY(vm_id) REFERENCES vms(vm_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS os_templates (
      template_id INTEGER PRIMARY KEY AUTOINCREMENT,
      template_key TEXT UNIQUE NOT NULL,
      template_name TEXT NOT NULL,
      template_type TEXT DEFAULT 'cloud-init',
      icon TEXT,
      description TEXT,
      disk_size TEXT DEFAULT '20G',
      memory INTEGER DEFAULT 2048,
      cpus INTEGER DEFAULT 2,
      download_url TEXT,
      local_path TEXT,
      username TEXT,
      password TEXT,
      is_custom BOOLEAN DEFAULT 0,
      is_active BOOLEAN DEFAULT 1,
      created_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(created_by) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      setting_key TEXT UNIQUE NOT NULL,
      setting_value TEXT,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Discord OAuth settings table
    db.run(`CREATE TABLE IF NOT EXISTS discord_settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      enabled BOOLEAN DEFAULT 0,
      client_id TEXT,
      client_secret TEXT,
      redirect_uri TEXT,
      bot_token TEXT,
      guild_id TEXT,
      auto_role_id TEXT,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Discord user accounts linking table
    db.run(`CREATE TABLE IF NOT EXISTS user_discord_accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL UNIQUE,
      discord_id TEXT UNIQUE NOT NULL,
      discord_username TEXT,
      discord_email TEXT,
      discord_avatar TEXT,
      connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // API Keys for external management
    db.run(`CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      api_key TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      permissions TEXT DEFAULT 'all',
      last_used DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      is_active BOOLEAN DEFAULT 1,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // Initialize default site settings if not exist
    const defaultSettings = {
      'site_name': 'HKVM Panel',
      'site_description': 'Virtual Machine Management System',
      'site_icon_url': 'https://i.imgur.com/0DmkSi4.png',
    };
    
    Object.entries(defaultSettings).forEach(([key, value]) => {
      db.get(`SELECT * FROM settings WHERE setting_key = ?`, [key], (err, row) => {
        if (!row) {
          db.run(`INSERT INTO settings (setting_key, setting_value) VALUES (?, ?)`, [key, value]);
        }
      });
    });

    // Add Discord columns to users table if they don't exist
    db.all(`PRAGMA table_info(users)`, (err, columns) => {
      if (columns) {
        const columnNames = columns.map(c => c.name);
        if (!columnNames.includes('discord_id')) {
          db.run(`ALTER TABLE users ADD COLUMN discord_id TEXT`, (err) => {
            if (!err) console.log('✓ Added column: discord_id');
          });
        }
      }
    });

    db.get(`SELECT * FROM users WHERE username = 'admin'`, (err, row) => {
      if (!row) {
        const hashedPassword = bcrypt.hashSync('admin', 10);
        db.run(`INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)`,
          ['admin', hashedPassword, 'admin@hopingboyz.local', 'admin']);
        console.log('✓ Default admin created: admin/admin (role: admin)');
      } else {
        console.log(`✓ Admin user exists: ${row.username} (role: ${row.role})`);
      }
    });
  });
}

// AUTH
// AUTH - Support both session cookies AND API keys
function checkAuth(req, res, next) {
  // Check if authenticated via session
  if (req.session && req.session.userId) {
    console.log(`[Auth Success] User ${req.session.userId} (${req.session.username}) accessing ${req.method} ${req.path} via session`);
    return next();
  }
  
  // Check if authenticated via API key
  if (req.apiKey && req.userId) {
    console.log(`[Auth Success] User ${req.userId} (${req.session?.username}) accessing ${req.method} ${req.path} via API key`);
    return next();
  }
  
  console.warn(`[Auth Error] Unauthenticated access attempt to ${req.method} ${req.path}`);
  
  // If API endpoint, return JSON error
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Unauthorized - provide X-API-Key header or login first' });
  }
  
  // Otherwise redirect to login
  return res.redirect('/login');
}

function checkAdmin(req, res, next) {
  // Check if authenticated
  if (!req.session && !req.apiKey) {
    console.warn(`[Auth Error] Unauthenticated access attempt to admin ${req.method} ${req.path}`);
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    return res.redirect('/login');
  }
  
  // Get role from session or API key
  const userId = req.session?.userId || req.userId;
  const role = req.session?.role || req.userRole;
  const username = req.session?.username || 'API User';
  
  if (role !== 'admin') {
    console.warn(`[Auth Error] Non-admin user ${userId} (${username}) attempted admin access to ${req.method} ${req.path}`);
    if (req.path.startsWith('/api/')) {
      return res.status(403).json({ error: 'Forbidden - admin access required' });
    }
    return res.redirect('/dashboard');
  }
  
  console.log(`[Admin Auth Success] Admin ${userId} (${username}) accessing ${req.method} ${req.path}`);
  next();
}

// API Key authentication middleware
function checkApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  
  if (!apiKey) {
    console.warn(`[API Auth Error] Missing API key in ${req.method} ${req.path}`);
    return res.status(401).json({ error: 'Missing API key' });
  }
  
  db.get(`SELECT * FROM api_keys WHERE api_key = ? AND is_active = 1`, [apiKey], (err, key) => {
    if (err) {
      console.error(`[API Auth Error] API key lookup failed:`, err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    if (!key) {
      console.warn(`[API Auth Error] Invalid or inactive API key`);
      return res.status(401).json({ error: 'Invalid API key' });
    }
    
    // Get user for the API key
    db.get(`SELECT * FROM users WHERE id = ?`, [key.user_id], (err, user) => {
      if (err || !user) {
        console.error(`[API Auth Error] User not found for API key`);
        return res.status(401).json({ error: 'User not found' });
      }
      
      // Update last used timestamp
      db.run(`UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?`, [key.id]);
      
      // Attach user and API key info to request
      req.apiKey = key;
      req.userId = key.user_id;
      req.userRole = user.role;
      
      console.log(`[API Auth Success] User ${user.id} (${user.username}) accessing ${req.method} ${req.path} via API key`);
      next();
    });
  });
}

// ============= AUTH ROUTES =============

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  console.log(`[Auth] Login attempt for username: ${username}`);
  
  db.get(`SELECT * FROM users WHERE username = ? AND is_active = 1`, [username], (err, user) => {
    if (err) {
      console.error(`[Auth Error] Login query failed for ${username}:`, err);
      return res.status(500).json({ error: err.message });
    }
    
    if (!user || !bcrypt.compareSync(password, user.password)) {
      console.warn(`[Auth Error] Invalid credentials for username: ${username}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [user.id], (err) => {
      if (err) console.error('[DB Error] Failed to update last_login:', err);
    });
    
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;
    console.log(`[Auth Success] User ${user.id} (${user.username}) logged in with role: ${user.role}`);
    res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
  });
});

app.post('/api/logout', (req, res) => {
  console.log(`[Auth] User ${req.session.userId} (${req.session.username}) logged out`);
  req.session.destroy(() => {
    console.log(`[Auth] Session destroyed`);
    res.json({ success: true });
  });
});

app.get('/api/auth/check', (req, res) => {
  if (req.session.userId) {
    res.json({ authenticated: true, user: { id: req.session.userId, username: req.session.username, role: req.session.role } });
  } else {
    res.json({ authenticated: false });
  }
});

// ============= DISCORD OAUTH ROUTES =============

const axios = require('axios');

// Get Discord OAuth state from session
function generateDiscordAuthUrl() {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM discord_settings WHERE enabled = 1`, (err, settings) => {
      if (err || !settings || !settings.client_id) {
        return reject(new Error('Discord auth not configured'));
      }

      const params = new URLSearchParams({
        client_id: settings.client_id,
        redirect_uri: settings.redirect_uri,
        response_type: 'code',
        scope: 'identify email',
        state: require('crypto').randomBytes(16).toString('hex')
      });

      resolve({
        url: `https://discord.com/api/oauth2/authorize?${params.toString()}`,
        state: params.get('state')
      });
    });
  });
}

// Check if Discord auth is enabled (public endpoint for login page)
app.get('/api/discord-enabled', (req, res) => {
  db.get(`SELECT enabled FROM discord_settings LIMIT 1`, (err, settings) => {
    if (err || !settings) {
      return res.json({ enabled: false });
    }
    res.json({ enabled: settings.enabled ? true : false });
  });
});

app.get('/api/discord-auth-url', checkAuth, async (req, res) => {
  try {
    const authData = await generateDiscordAuthUrl();
    req.session.discordState = authData.state;
    res.json({ url: authData.url });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  
  if (!code) {
    return res.redirect('/login?error=Discord authentication failed');
  }

  // Verify state to prevent CSRF
  if (state !== req.session.discordState) {
    console.error('[Discord Auth] State mismatch - possible CSRF attack');
    return res.redirect('/login?error=State validation failed');
  }

  try {
    // Get Discord settings
    const settings = await new Promise((resolve, reject) => {
      db.get(`SELECT * FROM discord_settings WHERE enabled = 1`, (err, s) => {
        if (err || !s) reject(new Error('Discord auth not configured'));
        else resolve(s);
      });
    });

    // Exchange code for token
    const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', {
      client_id: settings.client_id,
      client_secret: settings.client_secret,
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: settings.redirect_uri,
      scope: 'identify email'
    }, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const access_token = tokenResponse.data.access_token;

    // Get Discord user info
    const userResponse = await axios.get('https://discord.com/api/users/@me', {
      headers: { 'Authorization': `Bearer ${access_token}` }
    });

    const discordUser = userResponse.data;
    const discordId = discordUser.id;
    const discordUsername = discordUser.username;
    const discordEmail = discordUser.email;
    const discordAvatar = discordUser.avatar;

    console.log(`[Discord Auth] User ${discordUsername} (${discordId}) authenticated`);

    // Check if Discord account is already linked
    db.get(`SELECT * FROM user_discord_accounts WHERE discord_id = ?`, [discordId], (err, linked) => {
      if (err) {
        console.error('[Discord Auth] DB error:', err);
        return res.redirect('/login?error=Database error');
      }

      if (linked) {
        // Already linked - update avatar and log them in
        db.run(`UPDATE user_discord_accounts SET discord_avatar = ? WHERE discord_id = ?`, [discordAvatar || '', discordId], (err) => {
          if (err) console.error('[Discord Auth] Failed to update avatar:', err);
        });
        
        db.get(`SELECT * FROM users WHERE id = ?`, [linked.user_id], (err, user) => {
          if (err || !user) {
            return res.redirect('/login?error=User not found');
          }

          // Update last login
          db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [user.id]);

          req.session.userId = user.id;
          req.session.username = user.username;
          req.session.role = user.role;

          console.log(`[Discord Auth] User ${user.username} (${user.id}) logged in via Discord`);
          res.redirect('/dashboard');
        });
      } else {
        // Check if email exists in system
        if (discordEmail) {
          db.get(`SELECT * FROM users WHERE email = ?`, [discordEmail], (err, existingUser) => {
            if (err) {
              console.error('[Discord Auth] DB error:', err);
              return res.redirect('/login?error=Database error');
            }

            if (existingUser) {
              // Email exists - offer to link
              req.session.pendingDiscordAuth = {
                discordId: discordId,
                discordUsername: discordUsername,
                discordEmail: discordEmail,
                discordAvatar: discordAvatar,
                action: 'link'
              };
              res.redirect('/link-discord-account');
            } else {
              // New user - create account
              createDiscordUser(discordId, discordUsername, discordEmail, discordAvatar, res, req);
            }
          });
        } else {
          // No email - require manual creation
          req.session.pendingDiscordAuth = {
            discordId: discordId,
            discordUsername: discordUsername,
            discordEmail: discordEmail,
            discordAvatar: discordAvatar,
            action: 'create'
          };
          res.redirect('/create-account-discord');
        }
      }
    });
  } catch (err) {
    console.error('[Discord Auth] Error:', err.message);
    res.redirect('/login?error=' + encodeURIComponent(err.message));
  }
});

function createDiscordUser(discordId, discordUsername, discordEmail, discordAvatar, res, req) {
  // Generate a random password (user won't use it for Discord login)
  const tempPassword = require('crypto').randomBytes(16).toString('hex');
  const hashedPassword = bcrypt.hashSync(tempPassword, 10);

  db.run(
    `INSERT INTO users (username, password, email, full_name, role, is_active) VALUES (?, ?, ?, ?, ?, ?)`,
    [discordUsername, hashedPassword, discordEmail, discordUsername, 'user', 1],
    function(err) {
      if (err) {
        console.error('[Discord Auth] Failed to create user:', err);
        return res.redirect('/login?error=Failed to create account');
      }

      const userId = this.lastID;

      // Link Discord account
      db.run(
        `INSERT INTO user_discord_accounts (user_id, discord_id, discord_username, discord_email, discord_avatar) VALUES (?, ?, ?, ?, ?)`,
        [userId, discordId, discordUsername, discordEmail, discordAvatar || ''],
        (err) => {
          if (err) {
            console.error('[Discord Auth] Failed to link Discord account:', err);
            return res.redirect('/login?error=Failed to link account');
          }

          // Log them in
          db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [userId]);

          req.session.userId = userId;
          req.session.username = discordUsername;
          req.session.role = 'user';

          console.log(`[Discord Auth] New user ${discordUsername} (${userId}) created via Discord`);
          res.redirect('/dashboard');
        }
      );
    }
  );
}

// Link Discord to existing account (requires login first)
app.post('/api/link-discord-account', checkAuth, (req, res) => {
  if (!req.session.pendingDiscordAuth) {
    return res.status(400).json({ error: 'No pending Discord authentication' });
  }

  const { discordId, discordUsername, discordEmail, discordAvatar } = req.session.pendingDiscordAuth;
  const userId = req.session.userId;

  db.run(
    `INSERT OR REPLACE INTO user_discord_accounts (user_id, discord_id, discord_username, discord_email, discord_avatar) VALUES (?, ?, ?, ?, ?)`,
    [userId, discordId, discordUsername, discordEmail, discordAvatar || ''],
    (err) => {
      if (err) {
        console.error('[Discord Auth] Failed to link account:', err);
        return res.status(500).json({ error: err.message });
      }

      delete req.session.pendingDiscordAuth;
      console.log(`[Discord Auth] Linked Discord account ${discordUsername} to user ${userId}`);
      res.json({ success: true, message: 'Discord account linked successfully' });
    }
  );
});

// Unlink Discord account
app.post('/api/unlink-discord-account', checkAuth, (req, res) => {
  const userId = req.session.userId;

  db.run(`DELETE FROM user_discord_accounts WHERE user_id = ?`, [userId], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    console.log(`[Discord Auth] Unlinked Discord account from user ${userId}`);
    res.json({ success: true, message: 'Discord account unlinked' });
  });
});

// Get Discord account info
app.get('/api/discord-account-info', checkAuth, (req, res) => {
  const userId = req.session.userId;

  db.get(
    `SELECT discord_id, discord_username, discord_email, discord_avatar, connected_at FROM user_discord_accounts WHERE user_id = ?`,
    [userId],
    (err, account) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      // Return null if no Discord account linked, or the account object if linked
      if (!account) {
        return res.json(null);
      }
      res.json(account);
    }
  );
});

// ============= OS TEMPLATES =============

app.get('/api/os-templates', (req, res) => {
  // First get database templates
  db.all(`SELECT * FROM os_templates WHERE is_active = 1 ORDER BY created_at DESC`, (err, dbTemplates) => {
    if (err || !dbTemplates) {
      // If error, return default built-in templates only
      return res.json(OS_TEMPLATES);
    }

    // Combine DB templates with built-in templates
    const dbTemplateMap = {};
    if (dbTemplates && dbTemplates.length > 0) {
      dbTemplates.forEach(t => {
        dbTemplateMap[t.template_key] = t;
      });
    }

    // Get built-in templates as object
    const allTemplates = { ...OS_TEMPLATES };
    
    // Add custom templates from DB
    if (dbTemplates && dbTemplates.length > 0) {
      dbTemplates.forEach(t => {
        allTemplates[t.template_key] = {
          template_key: t.template_key,
          name: t.template_name,
          type: t.template_type,
          icon: t.icon,
          disk_size: t.disk_size,
          memory: t.memory,
          cpus: t.cpus,
          username: t.username,
          password: t.password || 'password',
          url: t.download_url,
          is_custom: true
        };
      });
    }

    res.json(allTemplates);
  });
});

// Get all templates (admin) - includes inactive
app.get('/api/admin/templates', checkAuth, checkAdmin, (req, res) => {
  console.log(`[API] GET /api/admin/templates - Admin requesting all templates`);
  
  // Query custom templates from database
  db.all(`SELECT * FROM os_templates ORDER BY is_custom DESC, created_at DESC`, [], (err, dbTemplates) => {
    if (err) {
      console.error(`[API] GET /api/admin/templates - DB Query Error:`, err.message);
      return res.status(500).json({ 
        error: 'Database error', 
        message: err.message,
        status: 'error'
      });
    }

    // Build built-in templates list
    const builtInList = [];
    for (const [key, template] of Object.entries(OS_TEMPLATES)) {
      builtInList.push({
        template_id: null,
        template_key: key,
        template_name: template.name,
        template_type: template.type,
        icon: template.icon,
        description: `Built-in template for ${template.name}`,
        disk_size: template.disk_size,
        memory: template.memory,
        cpus: template.cpus,
        download_url: template.url,
        local_path: null,
        username: template.username,
        password: template.password,
        is_custom: 0,
        is_active: 1,
        created_at: null,
        created_by: null
      });
    }

    // Combine: custom templates + built-in templates
    const allTemplates = [];
    
    // Add custom templates first
    if (dbTemplates && Array.isArray(dbTemplates)) {
      dbTemplates.forEach(t => {
        allTemplates.push({
          template_id: t.template_id,
          template_key: t.template_key,
          template_name: t.template_name,
          template_type: t.template_type,
          icon: t.icon,
          description: t.description,
          disk_size: t.disk_size,
          memory: t.memory,
          cpus: t.cpus,
          download_url: t.download_url,
          local_path: t.local_path,
          username: t.username,
          password: t.password,
          is_custom: t.is_custom,
          is_active: t.is_active,
          created_at: t.created_at,
          created_by: t.created_by
        });
      });
    }
    
    // Add built-in templates
    allTemplates.push(...builtInList);

    console.log(`[API] GET /api/admin/templates - Returning ${allTemplates.length} templates (${dbTemplates ? dbTemplates.length : 0} custom + ${builtInList.length} built-in)`);
    res.json(allTemplates);
  });
});

// Create custom template
app.post('/api/admin/templates', checkAuth, checkAdmin, async (req, res) => {
  const { template_key, template_name, template_type, icon, description, disk_size, memory, cpus, download_url, username, password } = req.body;

  if (!template_key || !template_name) {
    return res.status(400).json({ error: 'Template key and name are required' });
  }

  if (!disk_size) {
    return res.status(400).json({ error: 'Disk size is required' });
  }

  // Check if template key already exists
  db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [template_key], async (err, existing) => {
    if (existing) {
      return res.status(400).json({ error: 'Template with this key already exists' });
    }

    try {
      // Just store the template metadata - NO AUTO DOWNLOAD
      // User can download manually from templates list if needed
      const localPath = null; // Leave empty - user downloads manually

      // Insert into database
      db.run(
        `INSERT INTO os_templates 
        (template_key, template_name, template_type, icon, description, disk_size, memory, cpus, download_url, local_path, username, password, is_custom, created_by) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
        [template_key, template_name, template_type || 'cloud-init', icon || '📦', description || '', disk_size, memory || 2048, cpus || 2, download_url || '', localPath || '', username || '', password || '', req.session.userId],
        function(err) {
          if (err) return res.status(500).json({ error: err.message });
          
          res.json({
            success: true,
            template_id: this.lastID,
            template_key,
            message: 'Template created successfully! Download it manually from the templates list if needed.'
          });
        }
      );
    } catch (error) {
      res.status(500).json({ error: 'Failed to create template: ' + error.message });
    }
  });
});

// Update template
app.put('/api/admin/templates/:id', checkAuth, checkAdmin, (req, res) => {
  const { template_name, icon, description, disk_size, memory, cpus, username, password, is_active } = req.body;
  const templateId = req.params.id;

  const updates = [];
  const values = [];

  if (template_name) { updates.push('template_name = ?'); values.push(template_name); }
  if (icon !== undefined) { updates.push('icon = ?'); values.push(icon || '📦'); }
  if (description !== undefined) { updates.push('description = ?'); values.push(description || ''); }
  if (disk_size) { updates.push('disk_size = ?'); values.push(disk_size); }
  if (memory) { updates.push('memory = ?'); values.push(memory); }
  if (cpus) { updates.push('cpus = ?'); values.push(cpus); }
  if (username) { updates.push('username = ?'); values.push(username); }
  if (password) { updates.push('password = ?'); values.push(password); }
  if (is_active !== undefined) { updates.push('is_active = ?'); values.push(is_active ? 1 : 0); }
  
  updates.push('updated_at = datetime("now")');

  if (updates.length === 1) { // Only updated_at
    return res.status(400).json({ error: 'No fields to update' });
  }

  values.push(templateId);
  const query = `UPDATE os_templates SET ${updates.join(', ')} WHERE template_id = ?`;

  db.run(query, values, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, message: 'Template updated successfully' });
  });
});

// Update Built-in Template (creates/updates in database)
app.put('/api/admin/templates/builtin/:key', checkAuth, checkAdmin, (req, res) => {
  const templateKey = req.params.key;
  const { template_name, icon, description, disk_size, memory, cpus, username, password } = req.body;

  if (!OS_TEMPLATES[templateKey]) {
    return res.status(404).json({ error: 'Built-in template not found' });
  }

  const builtIn = OS_TEMPLATES[templateKey];

  // Check if already exists in database
  db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [templateKey], (err, existing) => {
    if (err) return res.status(500).json({ error: err.message });

    const finalData = {
      template_key: templateKey,
      template_name: template_name || builtIn.name,
      template_type: builtIn.type,
      icon: icon || builtIn.icon,
      description: description || `Built-in: ${builtIn.name}`,
      disk_size: disk_size || builtIn.disk_size,
      memory: memory || builtIn.memory,
      cpus: cpus || builtIn.cpus,
      download_url: builtIn.url,
      username: username || builtIn.username,
      password: password || builtIn.password,
      is_custom: 0
    };

    if (existing) {
      // Update existing
      db.run(
        `UPDATE os_templates SET 
         template_name = ?, icon = ?, description = ?, disk_size = ?, memory = ?, cpus = ?, 
         username = ?, password = ?, updated_at = datetime("now")
         WHERE template_key = ?`,
        [finalData.template_name, finalData.icon, finalData.description, finalData.disk_size, 
         finalData.memory, finalData.cpus, finalData.username, finalData.password, templateKey],
        (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ success: true, message: 'Built-in template updated successfully' });
        }
      );
    } else {
      // Insert new
      db.run(
        `INSERT INTO os_templates 
         (template_key, template_name, template_type, icon, description, disk_size, memory, cpus, 
          download_url, username, password, is_custom, created_by) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
        [finalData.template_key, finalData.template_name, finalData.template_type, finalData.icon, 
         finalData.description, finalData.disk_size, finalData.memory, finalData.cpus, 
         finalData.download_url, finalData.username, finalData.password, 1],
        (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ success: true, message: 'Built-in template saved successfully' });
        }
      );
    }
  });
});

// Delete template
app.delete('/api/admin/templates/:id', checkAuth, checkAdmin, (req, res) => {
  const templateId = req.params.id;

  db.get(`SELECT * FROM os_templates WHERE template_id = ?`, [templateId], (err, template) => {
    if (err || !template) return res.status(404).json({ error: 'Template not found' });

    // Delete local file if exists
    if (template.local_path && fs.existsSync(template.local_path)) {
      try {
        fs.unlinkSync(template.local_path);
      } catch (e) {
        console.error('Failed to delete template file:', e.message);
      }
    }

    // Delete from database
    db.run(`DELETE FROM os_templates WHERE template_id = ?`, [templateId], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, message: 'Template deleted successfully' });
    });
  });
});

// Download template file (get template by key) - with streaming progress
app.post('/api/admin/templates/:key/download', checkAuth, checkAdmin, async (req, res) => {
  const templateKey = req.params.key;

  try {
    // Check if it's a built-in template
    if (OS_TEMPLATES[templateKey]) {
      const template = OS_TEMPLATES[templateKey];
      const fileName = `${templateKey}-template.qcow2`;
      const localPath = path.join(TEMPLATES_DIR, fileName);

      // Create templates directory if it doesn't exist
      if (!fs.existsSync(TEMPLATES_DIR)) {
        fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
      }

      if (fs.existsSync(localPath)) {
        console.log(`[TEMPLATE] ${templateKey} already cached at ${localPath}`);
        res.setHeader('Content-Length', '2');
        return res.end('{}');
      }

      console.log(`[TEMPLATE] Starting download of ${templateKey} from ${template.url}`);

      // Download the template with streaming to client
      await downloadTemplateWithStreamingProgress(template.url, localPath, res);

      console.log(`[TEMPLATE] Download complete for ${templateKey}`);

      // Save to database
      db.run(
        `INSERT OR REPLACE INTO os_templates 
        (template_key, template_name, template_type, icon, description, disk_size, memory, cpus, download_url, local_path, username, password, is_custom) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
        [templateKey, template.name, template.type, template.icon, `Built-in: ${template.name}`, template.disk_size, template.memory, template.cpus, template.url, localPath, template.username, template.password],
        (err) => {
          if (err) console.error('Failed to save template to database:', err);
        }
      );
    } else {
      // Custom template
      db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [templateKey], async (err, template) => {
        if (err || !template) return res.status(404).json({ error: 'Template not found' });
        
        // Create templates directory if it doesn't exist
        if (!fs.existsSync(TEMPLATES_DIR)) {
          fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
        }

        // Generate local path if not set
        let localPath = template.local_path;
        if (!localPath) {
          // Extract filename from URL or use template key
          const urlParts = template.download_url.split('/');
          const fileName = urlParts[urlParts.length - 1] || `${templateKey}-template.qcow2`;
          localPath = path.join(TEMPLATES_DIR, fileName);
        }

        if (fs.existsSync(localPath)) {
          console.log(`[TEMPLATE] Custom template ${templateKey} already cached at ${localPath}`);
          
          // Update database with local path if not set
          if (!template.local_path) {
            db.run(`UPDATE os_templates SET local_path = ? WHERE template_key = ?`, 
              [localPath, templateKey], 
              (err) => {
                if (err) console.error('Failed to update template path:', err);
              }
            );
          }
          
          res.setHeader('Content-Length', '2');
          return res.end('{}');
        }

        // Download the template with streaming progress
        try {
          console.log(`[TEMPLATE] Starting download of custom template (${templateKey}) from ${template.download_url}`);
          console.log(`[TEMPLATE] Saving to: ${localPath}`);
          
          await downloadTemplateWithStreamingProgress(template.download_url, localPath, res);
          
          console.log(`[TEMPLATE] Download complete for custom template ${templateKey}`);

          // Update database with local path
          db.run(`UPDATE os_templates SET local_path = ? WHERE template_key = ?`, 
            [localPath, templateKey], 
            (err) => {
              if (err) console.error('Failed to update template path:', err);
            }
          );
        } catch (downloadErr) {
          console.error(`[TEMPLATE] Download error for ${templateKey}:`, downloadErr.message);
          if (!res.headersSent) {
            res.status(500).json({ error: 'Failed to download template: ' + downloadErr.message });
          }
        }
      });
    }
  } catch (error) {
    console.error(`[TEMPLATE] Error:`, error.message);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to download template: ' + error.message });
    }
  }
});

// Get template cache info
app.get('/api/admin/templates/cache/info', checkAuth, checkAdmin, (req, res) => {
  try {
    const templates = [];
    
    if (fs.existsSync(TEMPLATES_DIR)) {
      const files = fs.readdirSync(TEMPLATES_DIR);
      files.forEach(file => {
        const filePath = path.join(TEMPLATES_DIR, file);
        const stat = fs.statSync(filePath);
        templates.push({
          filename: file,
          size: stat.size,
          size_readable: (stat.size / (1024 * 1024 * 1024)).toFixed(2) + ' GB',
          created: stat.birthtime,
          modified: stat.mtime
        });
      });
    }

    res.json({
      cache_directory: TEMPLATES_DIR,
      templates: templates,
      total_count: templates.length,
      total_size: templates.reduce((sum, t) => sum + t.size, 0),
      total_size_readable: (templates.reduce((sum, t) => sum + t.size, 0) / (1024 * 1024 * 1024)).toFixed(2) + ' GB'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Clear template cache (admin only)
app.post('/api/admin/templates/cache/clear', checkAuth, checkAdmin, (req, res) => {
  try {
    if (!fs.existsSync(TEMPLATES_DIR)) {
      return res.json({ success: true, message: 'Cache directory does not exist' });
    }

    const files = fs.readdirSync(TEMPLATES_DIR);
    let deleted = 0;
    let errors = [];

    files.forEach(file => {
      const filePath = path.join(TEMPLATES_DIR, file);
      try {
        fs.unlinkSync(filePath);
        deleted++;
      } catch (e) {
        errors.push(file + ': ' + e.message);
      }
    });

    res.json({
      success: true,
      deleted: deleted,
      errors: errors.length > 0 ? errors : null,
      message: `Cleared ${deleted} cached templates`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get CPU Models
app.get('/api/cpu-models', (req, res) => {
  res.json(CPU_MODELS);
});

// Get SMBIOS options
app.get('/api/smbios', (req, res) => {
  res.json({
    manufacturers: SMBIOS_MANUFACTURERS,
    products: SMBIOS_PRODUCTS
  });
});

// Get Network Types
app.get('/api/network-types', (req, res) => {
  res.json(NETWORK_TYPES);
});

// Get DNS Providers
app.get('/api/dns-providers', (req, res) => {
  res.json(DNS_PROVIDERS);
});

// List available ISO files
app.get('/api/iso-list', (req, res) => {
  try {
    const files = fs.readdirSync(ISO_DIR).filter(f => f.endsWith('.iso'));
    res.json(files);
  } catch (error) {
    res.json([]);
  }
});

// ============= VIEW ROUTES (EJS Pages) =============

// Favicon endpoint
app.get('/favicon.ico', (req, res) => {
  res.redirect('/public/images/logo.png');
});

// Middleware to pass user and settings to all views
app.use((req, res, next) => {
  // Set defaults first
  res.locals.user = req.session.userId ? {
    id: req.session.userId,
    username: req.session.username,
    role: req.session.role
  } : null;
  
  // Panel version from .env
  res.locals.panelVersion = process.env.PANEL_VERSION || 'V3.0';
  
  // Set default logo and site name
  res.locals.siteLogo = process.env.DEFAULT_LOGO_URL || 'https://i.imgur.com/0DmkSi4.png';
  res.locals.siteName = process.env.PANEL_NAME || 'HKVM Panel';
  
  // Try to get site icon from database (non-blocking)
  db.get(`SELECT setting_value FROM settings WHERE setting_key = 'site_icon_url' LIMIT 1`, (err, row) => {
    if (row && row.setting_value) {
      res.locals.siteLogo = row.setting_value;
    }
  });
  
  // Try to get site name from database (non-blocking)
  db.get(`SELECT setting_value FROM settings WHERE setting_key = 'site_name' LIMIT 1`, (err, row2) => {
    if (row2 && row2.setting_value) {
      res.locals.siteName = row2.setting_value;
    }
  });
  
  next();
});

// Login page
app.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render('users/login', { 
    title: 'Login - HKVM Panel',
    currentPage: 'login',
    siteLogo: res.locals.siteLogo || process.env.DEFAULT_LOGO_URL || 'https://i.imgur.com/0DmkSi4.png',
    siteName: res.locals.siteName || process.env.PANEL_NAME || 'HKVM Panel'
  });
});



// Dashboard - Normal users only
app.get('/dashboard', checkAuth, (req, res) => {
  // Show user dashboard (works for both regular users and admins)
  res.render('users/dashboard', {
    title: 'My VMs - HKVM Panel',
    currentPage: 'dashboard',
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});
// Admin Dashboard - Admin only
app.get('/admin/dashboard', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/dashboard', {
    title: 'Dashboard - HKVM Panel',
    currentPage: 'dashboard',
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// Virtual Machines list (Admin only)
app.get('/admin/vms', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vms', {
    title: 'Virtual Machines - HKVM Panel',
    currentPage: 'vms'
  });
});

// Create VM (Admin only)
app.get('/admin/vm-create', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vm-create', {
    title: 'Create Virtual Machine - HKVM Panel',
    currentPage: 'vm-create',
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// VM Details (Admin only)
app.get('/admin/vm/:id', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vm-detail', {
    title: 'VM Details - HKVM Panel',
    currentPage: 'vm-detail',
    vmId: req.params.id
  });
});

// VM Console (Admin only)
app.get('/admin/vm/:id/console', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vm-console', {
    title: 'VM Console - HKVM Panel',
    currentPage: 'vm-console',
    vmId: req.params.id
  });
});

// VM Edit Configuration Page (Admin only)
app.get('/admin/vm/:id/edit', checkAuth, checkAdmin, (req, res) => {
  db.get(`SELECT * FROM vms WHERE vm_id = ?`, [req.params.id], (err, vm) => {
    if (err || !vm) return res.status(404).render('users/404', { message: 'VM not found' });
    
    res.render('admin/vm-edit', {
      title: 'Edit VM - HKVM Panel',
      currentPage: 'vm-edit',
      vmId: req.params.id,
      vm: vm
    });
  });
});

// Users management (admin only)
app.get('/admin/users', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/users', {
    title: 'Users - HKVM Panel',
    currentPage: 'users'
  });
});

// Create new user page (admin only)
app.get('/admin/users/create', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/users-create', {
    title: 'Create User - HKVM Panel',
    currentPage: 'users'
  });
});

// Edit user page (admin only)
app.get('/admin/users/:id/edit', checkAuth, checkAdmin, (req, res) => {
  const userId = parseInt(req.params.id);
  if (isNaN(userId)) {
    return res.status(400).render('admin/404', { title: 'Invalid User ID' });
  }
  
  res.render('admin/users-edit', {
    title: 'Edit User - HKVM Panel',
    currentPage: 'users',
    userId: userId
  });
});

// Settings (admin only)
app.get('/admin/settings', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/settings', {
    title: 'Settings - HKVM Panel',
    currentPage: 'settings'
  });
});

// OS Templates Management (admin only)
app.get('/admin/templates', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/templates', {
    title: 'OS Templates - HKVM Panel',
    currentPage: 'templates'
  });
});

// API Keys Management (admin only)
app.get('/admin/api-keys', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/api-keys', {
    title: 'API Keys - HKVM Panel',
    currentPage: 'api-keys',
    siteLogo: res.locals.siteLogo,
    baseUrl: `${req.protocol}://${req.get('host')}`,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// Add OS Template (admin only)
app.get('/admin/templates/add', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/templates-add', {
    title: 'Add OS Template - HKVM Panel',
    currentPage: 'templates'
  });
});

// Edit Built-in OS Template (admin only)
app.get('/admin/templates/builtin/:key/edit', checkAuth, checkAdmin, (req, res) => {
  const templateKey = req.params.key;
  console.log(`[ROUTE] GET /admin/templates/builtin/${templateKey}/edit`);
  
  if (!OS_TEMPLATES[templateKey]) {
    console.error(`[ERROR] Template key not found: ${templateKey}`);
    return res.status(400).render('admin/404', { title: 'Built-in Template Not Found' });
  }
  
  const template = OS_TEMPLATES[templateKey];
  console.log(`[SUCCESS] Found built-in template: ${template.name}`);
  
  // Build template object for display
  const templateObj = {
    template_key: templateKey,
    template_name: template.name,
    template_type: template.type,
    icon: template.icon,
    description: `Built-in template for ${template.name}`,
    disk_size: template.disk_size,
    memory: template.memory,
    cpus: template.cpus,
    download_url: template.url,
    username: template.username,
    password: template.password,
    is_custom: 0,
    is_builtin: 1
  };
  
  res.render('admin/templates-edit', {
    title: `View ${template.name} - HKVM Panel`,
    currentPage: 'templates',
    siteLogo: res.locals.siteLogo || 'https://i.imgur.com/0DmkSi4.png',
    templateKey: templateKey,
    isBuiltin: true,
    template: templateObj
  });
});

// ============= USER ROUTES (Non-Admin Users) =============

// User VMs list
app.get('/vms', checkAuth, (req, res) => {
  res.render('users/vms', {
    title: 'My Virtual Machines - HKVM Panel',
    currentPage: 'vms',
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// User VM detail page
app.get('/vm/:id', checkAuth, (req, res) => {
  res.render('users/vm-detail', {
    title: 'VM Details - HKVM Panel',
    currentPage: 'vm-detail',
    vmId: req.params.id,
    userId: req.session.userId,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// User VM console page
app.get('/vm/:id/console', checkAuth, (req, res) => {
  res.render('users/vm-console', {
    title: 'VM Console - HKVM Panel',
    currentPage: 'vm-console',
    vmId: req.params.id,
    userId: req.session.userId,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// User VM SSH connection page
app.get('/vm/:id/ssh', checkAuth, (req, res) => {
  res.render('users/vm-ssh', {
    title: 'SSH Connection - HKVM Panel',
    currentPage: 'vm-ssh',
    vmId: req.params.id,
    userId: req.session.userId,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// Admin VM SSH connection page
app.get('/admin/vm/:id/ssh', checkAuth, checkAdmin, (req, res) => {
  res.render('admin/vm-ssh', {
    title: 'SSH Connection - HKVM Admin Panel',
    currentPage: 'vm-ssh',
    vmId: req.params.id,
    userId: req.session.userId,
    user: {
      username: req.session.username,
      role: req.session.role
    }
  });
});

// User profile page
app.get('/profile', checkAuth, (req, res) => {
  res.render('users/profile', {
    title: 'My Profile - HKVM Panel',
    currentPage: 'profile',
    user: {
      username: req.session.username,
      role: req.session.role,
      userId: req.session.userId
    }
  });
});

// ============= API ROUTES =============

// Get list of users for dropdown/assignment (accessible to admins)
app.get('/api/users/list', checkAuth, checkAdmin, (req, res) => {
  db.all(`SELECT id, username, email, role FROM users WHERE is_active = 1 ORDER BY username`, (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(users);
  });
});

app.get('/api/admin/users', checkAuth, checkAdmin, (req, res) => {
  db.all(`SELECT id, username, email, role, created_at, is_active FROM users`, (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(users);
  });
});

// Get single user
app.get('/api/admin/users/:id', checkAuth, checkAdmin, (req, res) => {
  const userId = parseInt(req.params.id);
  db.get(`SELECT id, username, email, full_name, role, created_at, is_active FROM users WHERE id = ?`, [userId], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});

// Get user Discord info (for avatar display) - admin only
app.get('/api/admin/users/:id/discord-info', checkAuth, checkAdmin, (req, res) => {
  const userId = parseInt(req.params.id);
  db.get(
    `SELECT discord_id, discord_avatar FROM user_discord_accounts WHERE user_id = ?`,
    [userId],
    (err, discordAccount) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!discordAccount) return res.status(404).json({ error: 'No Discord account linked' });
      res.json(discordAccount);
    }
  );
});

app.post('/api/admin/users', checkAuth, checkAdmin, (req, res) => {
  const { username, password, email, full_name, role } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  const hashedPassword = bcrypt.hashSync(password, 10);
  db.run(
    `INSERT INTO users (username, password, email, full_name, role, is_active) VALUES (?, ?, ?, ?, ?, 1)`,
    [username, hashedPassword, email || null, full_name || null, role || 'user'],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: 'Username already exists' });
        }
        return res.status(500).json({ error: err.message });
      }
      res.json({ success: true, id: this.lastID });
    }
  );
});

// Update user
app.put('/api/admin/users/:id', checkAuth, checkAdmin, (req, res) => {
  const userId = parseInt(req.params.id);
  const { email, full_name, password, role, is_active } = req.body;
  
  if (userId === 1 && role && role !== 'admin') {
    return res.status(400).json({ error: 'Default admin must remain an admin' });
  }
  
  let query = 'UPDATE users SET ';
  let values = [];
  
  if (email !== undefined) {
    query += 'email = ?, ';
    values.push(email);
  }
  
  if (full_name !== undefined) {
    query += 'full_name = ?, ';
    values.push(full_name);
  }
  
  if (password) {
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    query += 'password = ?, ';
    values.push(bcrypt.hashSync(password, 10));
  }
  
  if (role !== undefined) {
    query += 'role = ?, ';
    values.push(role);
  }
  
  if (is_active !== undefined) {
    query += 'is_active = ?, ';
    values.push(is_active ? 1 : 0);
  }
  
  query = query.slice(0, -2); // Remove trailing comma and space
  query += ' WHERE id = ?';
  values.push(userId);
  
  db.run(query, values, (err) => {
    if (err) {
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(400).json({ error: 'Email already exists' });
      }
      return res.status(500).json({ error: err.message });
    }
    res.json({ success: true });
  });
});

app.delete('/api/admin/users/:id', checkAuth, checkAdmin, (req, res) => {
  if (req.params.id === '1') {
    return res.status(400).json({ error: 'Cannot delete default admin' });
  }
  db.run(`DELETE FROM users WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ============= API KEYS MANAGEMENT =============

// Generate new API key
app.post('/api/admin/api-keys', checkAuth, checkAdmin, (req, res) => {
  const { name, description } = req.body;
  const userId = req.session.userId;
  
  if (!name) {
    return res.status(400).json({ error: 'API key name is required' });
  }
  
  // Generate random API key
  const apiKey = 'hk_' + require('crypto').randomBytes(24).toString('hex');
  
  db.run(
    `INSERT INTO api_keys (user_id, api_key, name, description, permissions) 
     VALUES (?, ?, ?, ?, ?)`,
    [userId, apiKey, name, description || '', 'all'],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      
      res.json({
        success: true,
        id: this.lastID,
        api_key: apiKey,
        name: name,
        description: description,
        message: 'API key created successfully. Save this key securely!'
      });
    }
  );
});

// Get all API keys for current user
app.get('/api/admin/api-keys', checkAuth, checkAdmin, (req, res) => {
  const userId = req.session.userId;
  
  db.all(
    `SELECT id, api_key, name, description, permissions, last_used, created_at, is_active
     FROM api_keys 
     WHERE user_id = ?
     ORDER BY created_at DESC`,
    [userId],
    (err, keys) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(keys || []);
    }
  );
});

// Delete API key
app.delete('/api/admin/api-keys/:id', checkAuth, checkAdmin, (req, res) => {
  const userId = req.session.userId;
  const keyId = req.params.id;
  
  db.get(`SELECT * FROM api_keys WHERE id = ? AND user_id = ?`, [keyId, userId], (err, key) => {
    if (err || !key) return res.status(404).json({ error: 'API key not found' });
    
    db.run(`DELETE FROM api_keys WHERE id = ?`, [keyId], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, message: 'API key deleted' });
    });
  });
});

// Revoke/Deactivate API key
app.post('/api/admin/api-keys/:id/revoke', checkAuth, checkAdmin, (req, res) => {
  const userId = req.session.userId;
  const keyId = req.params.id;
  
  db.get(`SELECT * FROM api_keys WHERE id = ? AND user_id = ?`, [keyId, userId], (err, key) => {
    if (err || !key) return res.status(404).json({ error: 'API key not found' });
    
    db.run(`UPDATE api_keys SET is_active = 0 WHERE id = ?`, [keyId], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, message: 'API key revoked' });
    });
  });
});

// ============= ACCOUNT LINKING & API AUTHENTICATION =============

/**
 * POST /api/account/link
 * Link HKVM account to generate API key
 * Validates username, email, and password
 * Returns: { success: true, api_key, user: {...}, message }
 * 
 * This endpoint allows users to authenticate with their credentials
 * and receive an API key for programmatic access
 */
app.post('/api/account/link', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Validate input
    if (!username || !password) {
      return res.status(400).json({ 
        error: 'Username and password are required' 
      });
    }

    // Look up user by username
    db.get(
      `SELECT id, username, email, password, role, is_active FROM users WHERE username = ? AND is_active = 1`,
      [username],
      async (err, user) => {
        if (err) {
          console.error('[Account Link] Database error:', err);
          return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
          console.warn(`[Account Link] User not found: ${username}`);
          return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Verify password
        if (!bcrypt.compareSync(password, user.password)) {
          console.warn(`[Account Link] Password mismatch for user: ${username}`);
          return res.status(401).json({ error: 'Invalid username or password' });
        }

        // If email provided, verify it matches
        if (email && user.email !== email) {
          console.warn(`[Account Link] Email mismatch for user ${username}: provided=${email}, stored=${user.email}`);
          return res.status(401).json({ error: 'Email does not match account' });
        }

        // Generate new API key
        const crypto = require('crypto');
        const apiKey = 'hk_' + crypto.randomBytes(24).toString('hex');
        const keyName = `linked_${username}_${Date.now()}`;

        // Save API key to database
        db.run(
          `INSERT INTO api_keys (user_id, api_key, name, description, permissions, is_active) 
           VALUES (?, ?, ?, ?, ?, 1)`,
          [
            user.id, 
            apiKey, 
            keyName,
            `Account link key for ${username}`,
            'all'
          ],
          function(err) {
            if (err) {
              console.error('[Account Link] Failed to create API key:', err);
              return res.status(500).json({ error: 'Failed to create API key' });
            }

            console.log(`[Account Link] ✓ API key generated for user ${user.id} (${username})`);

            // Update last login
            db.run(
              `UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`,
              [user.id]
            );

            // Return success with API key and user info
            res.json({
              success: true,
              api_key: apiKey,
              user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
              },
              message: 'Account linked successfully. Use the API key for API authentication.'
            });
          }
        );
      }
    );
  } catch (error) {
    console.error('[Account Link] Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/account/validate
 * Validate account credentials and get user info
 * Does NOT generate API key - just validates credentials
 * Returns: { success: true, user: {...} }
 * 
 * Use this to verify user credentials without creating a key
 */
app.post('/api/account/validate', (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password) {
      return res.status(400).json({ 
        error: 'Username and password are required' 
      });
    }

    db.get(
      `SELECT id, username, email, password, role, is_active, created_at, last_login 
       FROM users WHERE username = ? AND is_active = 1`,
      [username],
      (err, user) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
          return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Verify password
        if (!bcrypt.compareSync(password, user.password)) {
          return res.status(401).json({ error: 'Invalid username or password' });
        }

        // If email provided, verify it matches
        if (email && user.email !== email) {
          return res.status(401).json({ error: 'Email does not match account' });
        }

        console.log(`[Account Validate] ✓ Credentials valid for user ${user.id} (${user.username})`);

        // Return user info without password
        res.json({
          success: true,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            created_at: user.created_at,
            last_login: user.last_login
          },
          message: 'Credentials validated successfully'
        });
      }
    );
  } catch (error) {
    console.error('[Account Validate] Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/account/api-keys (requires checkAuth)
 * List all API keys for current user
 * Can use session OR API key authentication
 * Returns: [{ id, name, description, created_at, is_active, last_used }, ...]
 */
app.get('/api/account/api-keys', checkAuth, (req, res) => {
  const userId = req.session?.userId || req.userId;

  if (!userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  db.all(
    `SELECT id, name, description, created_at, is_active, last_used 
     FROM api_keys 
     WHERE user_id = ? 
     ORDER BY created_at DESC`,
    [userId],
    (err, keys) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      res.json({
        success: true,
        keys: keys || [],
        count: (keys || []).length
      });
    }
  );
});

/**
 * DELETE /api/account/api-keys/:id (requires checkAuth)
 * Remove an API key
 * Can use session OR API key authentication
 * Returns: { success: true, message }
 */
app.delete('/api/account/api-keys/:id', checkAuth, (req, res) => {
  const userId = req.session?.userId || req.userId;
  const keyId = req.params.id;

  if (!userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  db.get(
    `SELECT * FROM api_keys WHERE id = ? AND user_id = ?`,
    [keyId, userId],
    (err, key) => {
      if (err || !key) {
        return res.status(404).json({ error: 'API key not found' });
      }

      db.run(
        `DELETE FROM api_keys WHERE id = ?`,
        [keyId],
        (err) => {
          if (err) {
            return res.status(500).json({ error: err.message });
          }

          console.log(`[Account API Keys] ✓ API key ${keyId} deleted for user ${userId}`);
          res.json({ 
            success: true, 
            message: 'API key deleted successfully' 
          });
        }
      );
    }
  );
});

/**
 * POST /api/account/api-keys/:id/revoke (requires checkAuth)
 * Deactivate an API key (keeps record)
 * Can use session OR API key authentication
 * Returns: { success: true, message }
 */
app.post('/api/account/api-keys/:id/revoke', checkAuth, (req, res) => {
  const userId = req.session?.userId || req.userId;
  const keyId = req.params.id;

  if (!userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  db.get(
    `SELECT * FROM api_keys WHERE id = ? AND user_id = ?`,
    [keyId, userId],
    (err, key) => {
      if (err || !key) {
        return res.status(404).json({ error: 'API key not found' });
      }

      db.run(
        `UPDATE api_keys SET is_active = 0 WHERE id = ?`,
        [keyId],
        (err) => {
          if (err) {
            return res.status(500).json({ error: err.message });
          }

          console.log(`[Account API Keys] ✓ API key ${keyId} revoked for user ${userId}`);
          res.json({ 
            success: true, 
            message: 'API key revoked successfully' 
          });
        }
      );
    }
  );
});

// ============= VM MANAGEMENT (VM ID BASED) =============

app.get('/api/vms', checkAuth, (req, res) => {
  const userId = req.session.userId;
  
  // User pages always show ONLY the logged-in user's own VMs
  // (even if user is admin - they see their own VMs, not all VMs)
  // For all VMs, use /api/admin/vms endpoint
  let query = `SELECT vms.*, COALESCE(t.icon, '⚫') as template_icon, COALESCE(t.template_name, vms.os_type) as template_name
              FROM vms 
              LEFT JOIN os_templates t ON vms.template_type = t.template_key
              WHERE vms.owner_id = ?
              ORDER BY vms.vm_id DESC`;
  let params = [userId];
  
  db.all(query, params, (err, vms) => {
    if (err) {
      console.error('[API Error] /api/vms:', err);
      return res.status(500).json({ error: err.message });
    }
    console.log(`[API Success] /api/vms: User ${userId} (${req.session.role}) fetched ${vms ? vms.length : 0} VMs (own VMs only)`);
    res.json(vms || []);
  });
});

// Admin API endpoint: Get all VMs for admin pages
app.get('/api/admin/vms', checkAuth, checkAdmin, (req, res) => {
  const userId = req.session.userId;
  
  // Admin pages can see ALL VMs in the system
  let query = `SELECT vms.*, COALESCE(t.icon, '⚫') as template_icon, COALESCE(t.template_name, vms.os_type) as template_name
              FROM vms 
              LEFT JOIN os_templates t ON vms.template_type = t.template_key
              ORDER BY vms.vm_id DESC`;
  let params = [];
  
  db.all(query, params, (err, vms) => {
    if (err) {
      console.error('[API Error] /api/admin/vms:', err);
      return res.status(500).json({ error: err.message });
    }
    console.log(`[API Success] /api/admin/vms: Admin ${userId} fetched ${vms ? vms.length : 0} VMs (all VMs)`);
    res.json(vms || []);
  });
});

app.get('/api/vms/:vm_id', checkAuth, (req, res) => {
  const userId = req.session.userId;
  let query = `
    SELECT 
      vms.*,
      COALESCE(vms.ipv4_gateway, vms.gateway) as gateway,
      COALESCE(ot.icon, '⚫') as template_icon
    FROM vms
    LEFT JOIN os_templates ot ON vms.template_type = ot.template_key
    WHERE vms.vm_id = ?
  `;
  let params = [req.params.vm_id];
  
  // Normal users can only see their own VMs
  if (req.session.role !== 'admin') {
    query += ` AND vms.owner_id = ?`;
    params.push(userId);
  }
  
  db.get(query, params, (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });
    res.json(vm);
  });
});

// VM CONSOLE - Stream last 100 lines of VM serial output
app.get('/api/vms/:vm_id/console', checkAuth, (req, res) => {
  const vm_id = req.params.vm_id;
  
  // Get VM to find custom disk path
  db.get(`SELECT vm_disk_path FROM vms WHERE vm_id = ?`, [vm_id], (err, vm) => {
    if (err) return res.status(500).json({ error: err.message });
    
    const vmDiskPath = (vm && vm.vm_disk_path) ? vm.vm_disk_path : VM_DIR;
    const logFile = path.join(vmDiskPath, `vm-${vm_id}.log`);
  
    if (!fs.existsSync(logFile)) {
      return res.json({ vm_id: vm_id, logs: 'Console not available yet', lines: 0 });
    }
    
    try {
      const logs = fs.readFileSync(logFile, 'utf8');
      const lines = logs.split('\n');
      const last100 = lines.slice(-100).join('\n');
      res.json({
        vm_id: vm_id,
        logs: last100,
        total_lines: lines.length
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
});

// VM CONSOLE COMMAND - Send command to VM via serial console
app.post('/api/vms/:vm_id/console/command', checkAuth, async (req, res) => {
  const vm_id = req.params.vm_id;
  const { command } = req.body;
  const userId = req.session.userId;

  if (!command) {
    return res.status(400).json({ error: 'Command required' });
  }

  let query = `SELECT * FROM vms WHERE vm_id = ?`;
  let params = [vm_id];
  
  // Normal users can only send commands to their own VMs
  if (req.session.role !== 'admin') {
    query += ` AND owner_id = ?`;
    params.push(userId);
  }

  db.get(query, params, async (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });

    if (vm.status !== 'running') {
      return res.status(400).json({ error: 'VM is not running' });
    }

    try {
      // Command is sent via WebSocket to console
      // Append to log so it appears in console
      const vmDiskPath = vm.vm_disk_path || VM_DIR;
      const logFile = path.join(vmDiskPath, `vm-${vm_id}.log`);
      fs.appendFileSync(logFile, command);
      
      console.log(`[VM-${vm_id}] Command executed: ${command}`);
      res.json({ 
        success: true, 
        message: 'Command sent to VM console',
        command: command,
        vmId: vm_id
      });
    } catch (error) {
      console.error(`[VM-${vm_id}] Error sending command:`, error.message);
      res.status(500).json({ error: 'Failed to send command: ' + error.message });
    }
  });
});

// GET VM EDIT CONFIG (retrieve editable fields)
app.get('/api/vms/:vm_id/edit', checkAuth, (req, res) => {
  db.get(`SELECT * FROM vms WHERE vm_id = ?`, [req.params.vm_id], (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found' });
    
    // Return editable fields
    res.json({
      vm_id: vm.vm_id,
      vm_name: vm.vm_name,
      hostname: vm.hostname,
      memory: vm.memory,
      cpus: vm.cpus,
      cpu_sockets: vm.cpu_sockets,
      cpu_cores: vm.cpu_cores,
      cpu_threads: vm.cpu_threads,
      cpu_model: vm.cpu_model,
      disk_size: vm.disk_size,
      status: vm.status,
      enable_acpi: vm.enable_acpi,
      enable_kvm: vm.enable_kvm,
      extra_args: vm.extra_args,
      network_type: vm.network_type,
      ipv4_address: vm.ipv4_address,
      ipv4_gateway: vm.ipv4_gateway,
      ipv4_netmask: vm.ipv4_netmask,
      dns_primary: vm.dns_primary,
      dns_secondary: vm.dns_secondary,
      ipv6_address: vm.ipv6_address,
      ipv6_gateway: vm.ipv6_gateway,
      mac_address: vm.mac_address,
      vlan_id: vm.vlan_id,
      can_edit: vm.status === 'stopped'
    });
  });
});

// Resize disk qcow2 file (expand or shrink)
async function resizeDisk(vm_id, diskFilePath, newSize) {
  return new Promise((resolve, reject) => {
    try {
      if (!fs.existsSync(diskFilePath)) {
        return reject(new Error('Disk file not found'));
      }

      // Parse size to bytes (handle G, GB, T, TB)
      const parseSize = (sizeStr) => {
        const match = sizeStr.match(/^(\d+(?:\.\d+)?)\s*([KMGT]?B?)$/i);
        if (!match) return null;
        
        let size = parseFloat(match[1]);
        const unit = (match[2] || '').toUpperCase();
        
        const multipliers = { 'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4 };
        if (unit.startsWith('K')) size *= multipliers['K'];
        else if (unit.startsWith('M')) size *= multipliers['M'];
        else if (unit.startsWith('G')) size *= multipliers['G'];
        else if (unit.startsWith('T')) size *= multipliers['T'];
        
        return Math.floor(size);
      };

      const newSizeBytes = parseSize(newSize);
      if (!newSizeBytes) {
        return reject(new Error('Invalid size format. Use: 20G, 100GB, 1T, etc.'));
      }

      // Get current disk size from qemu-img (not file size, but virtual size)
      let currentSize;
      try {
        const infoOutput = execSync(`qemu-img info "${diskFilePath}" --output=json`, { stdio: 'pipe', encoding: 'utf8' });
        const imageInfo = JSON.parse(infoOutput);
        currentSize = imageInfo['virtual-size'] || imageInfo['VirtualSize'] || 0;
        console.log(`[DISK-${vm_id}] Detected via qemu-img: Virtual size = ${(currentSize / (1024**3)).toFixed(2)}GB`);
      } catch (err) {
        console.warn(`[DISK-${vm_id}] Could not get size from qemu-img, falling back to file size`);
        const stats = fs.statSync(diskFilePath);
        currentSize = stats.size;
      }

      console.log(`[DISK-${vm_id}] Current: ${(currentSize / (1024**3)).toFixed(2)}GB, Target: ${(newSizeBytes / (1024**3)).toFixed(2)}GB`);

      if (newSizeBytes === currentSize) {
        return resolve({ message: 'size unchanged' });
      }

      // Determine if we're expanding or shrinking
      const isShrink = newSizeBytes < currentSize;
      const operation = isShrink ? 'shrink' : 'expand';

      // Use qemu-img to resize - always use +SIZE syntax for expand, =SIZE for shrink
      let resizeCmd;
      if (isShrink) {
        // Shrinking requires --shrink flag and = syntax
        resizeCmd = `qemu-img resize --shrink "${diskFilePath}" ${newSize}`;
      } else {
        // Expanding - use = syntax (not + syntax)
        resizeCmd = `qemu-img resize "${diskFilePath}" ${newSize}`;
      }

      console.log(`[DISK-${vm_id}] ${operation.toUpperCase()}: Executing: ${resizeCmd}`);
      
      // Execute and capture both stdout and stderr
      let output;
      try {
        output = execSync(resizeCmd, { stdio: 'pipe', encoding: 'utf8', shell: true });
        console.log(`[DISK-${vm_id}] Command output: ${output}`);
      } catch (execErr) {
        // Check if it's just a warning
        const stderr = execErr.stderr ? execErr.stderr.toString() : '';
        const stdout = execErr.stdout ? execErr.stdout.toString() : '';
        
        // If it's a shrink warning, it might still work
        if (isShrink && stderr.includes('Shrinking an image')) {
          console.log(`[DISK-${vm_id}] Shrink warning (expected):`, stderr);
        } else {
          throw execErr;
        }
      }

      console.log(`[DISK-${vm_id}] Disk ${operation}ed to ${newSize}`);
      resolve({ message: `${operation}ed to ${newSize}` });
    } catch (err) {
      reject(err);
    }
  });
}

// Regenerate cloud-init seed for a VM

// UPDATE VM CONFIGURATION (PUT request)
app.put('/api/vms/:vm_id/edit', checkAuth, (req, res) => {
  const vm_id = req.params.vm_id;
  const userId = req.session.userId;
  const {
    vm_name, hostname, memory, cpus, cpu_sockets, cpu_cores, cpu_threads, cpu_model,
    custom_cpu_name, username, password,
    disk_size, enable_acpi, enable_kvm, extra_args,
    network_type, ipv4_address, ipv4_gateway, ipv4_netmask, bridge_device,
    dns_primary, dns_secondary, ipv6_address, ipv6_gateway, mac_address, vlan_id,
    machine_type, board_name, product_name, custom_smbios_manufacturer,
    smbios_manufacturer, smbios_product, smbios_version, smbios_serial,
    ssh_port, ssh_port_static,
    owner_id
  } = req.body;

  console.log(`[VM-${vm_id}] Edit request - disk_size: '${disk_size}', hostname: '${hostname}', username: '${username}', password: '${password}'`);
  console.log(`[VM-${vm_id}] Full body fields:`, Object.keys(req.body));

  let query = `SELECT status, template_type, seed_file FROM vms WHERE vm_id = ?`;
  let params = [vm_id];
  
  // Normal users can only edit their own VMs
  if (req.session.role !== 'admin') {
    query += ` AND owner_id = ?`;
    params.push(userId);
  }

  db.get(query, params, (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });
    
    // Only allow editing stopped VMs
    if (vm.status !== 'stopped') {
      return res.status(400).json({ error: 'VM must be stopped to edit configuration' });
    }

    // Store original VM state for change detection
    const originalVm = { ...vm };

    // Validate inputs - remove strict limits, allow any positive values
    const validatedMemory = memory ? parseInt(memory) : undefined;
    if (validatedMemory && validatedMemory < 1) {
      return res.status(400).json({ error: 'Memory must be at least 1 MB' });
    }
    
    const validatedCpus = cpus ? parseInt(cpus) : undefined;
    if (validatedCpus && validatedCpus < 1) {
      return res.status(400).json({ error: 'CPUs must be at least 1' });
    }
    
    const validatedSockets = cpu_sockets && cpu_sockets >= 1 ? cpu_sockets : undefined;
    const validatedCores = cpu_cores && cpu_cores >= 1 ? cpu_cores : undefined;
    const validatedThreads = cpu_threads && cpu_threads >= 1 ? cpu_threads : undefined;

    // Build update query dynamically
    const updates = [];
    const values = [];

    if (vm_name) { updates.push('vm_name = ?'); values.push(vm_name); }
    if (hostname !== undefined && hostname !== null) { updates.push('hostname = ?'); values.push(hostname); }
    if (validatedMemory) { updates.push('memory = ?'); values.push(validatedMemory); }
    if (validatedCpus) { updates.push('cpus = ?'); values.push(validatedCpus); }
    if (validatedSockets) { updates.push('cpu_sockets = ?'); values.push(validatedSockets); }
    if (validatedCores) { updates.push('cpu_cores = ?'); values.push(validatedCores); }
    if (validatedThreads) { updates.push('cpu_threads = ?'); values.push(validatedThreads); }
    if (cpu_model) { updates.push('cpu_model = ?'); values.push(cpu_model); }
    
    // Debug disk_size
    console.log(`[VM-${vm_id}] Checking disk_size: disk_size='${disk_size}', undefined=${disk_size === undefined}, null=${disk_size === null}`);
    if (disk_size !== undefined && disk_size !== null) { 
      console.log(`[VM-${vm_id}] ✓ Adding disk_size to updates: '${disk_size}'`);
      updates.push('disk_size = ?'); 
      values.push(disk_size); 
    } else {
      console.log(`[VM-${vm_id}] ✗ Skipping disk_size (condition failed)`);
    }
    // Allow empty username/password to keep existing values, but update if provided
    if (username !== undefined && username !== null) { updates.push('username = ?'); values.push(username); }
    if (password !== undefined && password !== null) { updates.push('password = ?'); values.push(password); }
    if (enable_acpi !== undefined) { updates.push('enable_acpi = ?'); values.push(enable_acpi ? 1 : 0); }
    if (enable_kvm !== undefined) { updates.push('enable_kvm = ?'); values.push(enable_kvm ? 1 : 0); }
    if (extra_args !== undefined) { updates.push('extra_args = ?'); values.push(extra_args || ''); }
    if (network_type) { updates.push('network_type = ?'); values.push(network_type); }
    if (ipv4_address !== undefined) { updates.push('ipv4_address = ?'); values.push(ipv4_address); }
    if (ipv4_gateway !== undefined) { updates.push('ipv4_gateway = ?'); values.push(ipv4_gateway); }
    if (ipv4_netmask !== undefined) { updates.push('ipv4_netmask = ?'); values.push(ipv4_netmask); }
    if (bridge_device !== undefined) { updates.push('bridge_device = ?'); values.push(bridge_device || 'vmbr0'); }
    if (dns_primary !== undefined && dns_primary !== null) { updates.push('dns_primary = ?'); values.push(dns_primary); }
    if (dns_secondary !== undefined && dns_secondary !== null) { updates.push('dns_secondary = ?'); values.push(dns_secondary); }
    if (ipv6_address !== undefined) { updates.push('ipv6_address = ?'); values.push(ipv6_address); }
    if (ipv6_gateway !== undefined) { updates.push('ipv6_gateway = ?'); values.push(ipv6_gateway); }
    if (mac_address) { updates.push('mac_address = ?'); values.push(mac_address); }
    if (vlan_id !== undefined) { updates.push('vlan_id = ?'); values.push(vlan_id); }
    if (custom_cpu_name) { updates.push('custom_cpu_name = ?'); values.push(custom_cpu_name); }
    if (board_name) { updates.push('board_name = ?'); values.push(board_name); }
    if (product_name) { updates.push('product_name = ?'); values.push(product_name); }
    if (machine_type) { updates.push('machine_type = ?'); values.push(machine_type); }
    if (smbios_manufacturer) { updates.push('smbios_manufacturer = ?'); values.push(smbios_manufacturer); }
    if (smbios_product) { updates.push('smbios_product = ?'); values.push(smbios_product); }
    if (smbios_version) { updates.push('smbios_version = ?'); values.push(smbios_version); }
    if (smbios_serial) { updates.push('smbios_serial = ?'); values.push(smbios_serial); }
    
    // Handle SSH port - prefer ssh_port_static if provided, else use ssh_port
    if (ssh_port_static !== undefined) { updates.push('ssh_port_static = ?'); values.push(ssh_port_static); }
    if (ssh_port !== undefined) { updates.push('ssh_port = ?'); values.push(ssh_port); }
    
    // Only admins can change owner
    if (owner_id !== undefined && req.session.role === 'admin') {
      updates.push('owner_id = ?');
      values.push(owner_id || null); // Allow null to clear owner
      console.log(`[VM ${vm_id}] Admin changing owner to ${owner_id || 'null'}`);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    values.push(vm_id);
    const query = `UPDATE vms SET ${updates.join(', ')} WHERE vm_id = ?`;
    
    console.log(`[VM-${vm_id}] Updates to apply:`, updates);
    console.log(`[VM-${vm_id}] Values:`, values);

    db.run(query, values, async (err) => {
      if (err) {
        console.error(`[VM-${vm_id}] ✗ Database update failed: ${err.message}`);
        return res.status(500).json({ error: err.message });
      }
      
      console.log(`[VM-${vm_id}] ✓ Database update successful! Updated fields applied.`);
      
      // Fetch updated VM to get current disk_file path
      db.get(`SELECT disk_file FROM vms WHERE vm_id = ?`, [vm_id], (err, currentVm) => {
        if (!err && currentVm && currentVm.disk_file) {
          // Check if disk_size was changed
          if (disk_size && disk_size !== originalVm.disk_size && fs.existsSync(currentVm.disk_file)) {
            console.log(`[VM-${vm_id}] 🔧 Disk size change detected: '${originalVm.disk_size}' → '${disk_size}'`);
            console.log(`[VM-${vm_id}] Disk file path: ${currentVm.disk_file}`);
            console.log(`[VM-${vm_id}] Disk file exists: ${fs.existsSync(currentVm.disk_file)}`);
            
            resizeDisk(vm_id, currentVm.disk_file, disk_size)
              .then((result) => {
                console.log(`[VM-${vm_id}] ✅ Disk resize successful: ${result.message}`);
                logVMAction(vm_id, 'edit', 'success', `Disk resized to ${disk_size}. ${result.message}`);
              })
              .catch((diskErr) => {
                console.error(`[VM-${vm_id}] ❌ Disk resize failed: ${diskErr.message}`);
                logVMAction(vm_id, 'edit', 'warning', `Disk resize failed: ${diskErr.message}`);
              });
          } else {
            console.log(`[VM-${vm_id}] No disk resize needed. disk_size: ${disk_size}, originalSize: ${originalVm.disk_size}, diskFileExists: ${fs.existsSync(currentVm.disk_file || '')}`);
          }
        }
      });
      
      try {
        // Delete old seed ISO and create new one with current config
        console.log(`[VM-${vm_id}] Template type check: '${originalVm.template_type}'`);
        
        // Always regenerate regardless of template_type
        console.log(`[VM-${vm_id}] ✓ Regenerating seed with current configuration...`);
        
        // Always delete old seed ISO first
        const seedIsoPath = path.join(VM_DIR, `vm-${vm_id}-seed.iso`);
        console.log(`[VM-${vm_id}] Checking for old seed: ${seedIsoPath}`);
        
        if (fs.existsSync(seedIsoPath)) {
          try {
            fs.unlinkSync(seedIsoPath);
            console.log(`[VM-${vm_id}] ✓ Deleted old seed ISO: ${seedIsoPath}`);
          } catch (delErr) {
            console.error(`[VM-${vm_id}] Failed to delete old seed: ${delErr.message}`);
          }
        } else {
          console.log(`[VM-${vm_id}] Old seed not found (OK if first time)`);
        }
        
        // Fetch updated VM with new config and create new seed ISO
        db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vm_id], (err, updatedVm) => {
          if (err) {
            console.error(`[VM-${vm_id}] Failed to fetch updated VM:`, err.message);
            return;
          }
          
          if (!updatedVm) {
            console.error(`[VM-${vm_id}] Updated VM not found in database`);
            return;
          }
          
          console.log(`[VM-${vm_id}] Creating new seed ISO with config - network_type: ${updatedVm.network_type}, ipv4: ${updatedVm.ipv4_address}, gateway: ${updatedVm.ipv4_gateway || updatedVm.gateway}`);
          
          createCloudInitSeed(vm_id, updatedVm)
            .then(() => {
              console.log(`[VM-${vm_id}] ✓ New cloud-init seed ISO created successfully`);
              logVMAction(vm_id, 'edit', 'success', `Cloud-init seed regenerated with updated configuration. Changes will apply on next VM boot.`);
            })
            .catch(seedErr => {
              console.error(`[VM-${vm_id}] ✗ Failed to create cloud-init seed: ${seedErr.message}`);
              logVMAction(vm_id, 'edit', 'warning', `Configuration updated but cloud-init seed creation failed: ${seedErr.message}`);
            });
        });
      } catch (err) {
        console.error(`[VM-${vm_id}] Error during seed regeneration:`, err.message);
      }
      
      res.json({ success: true, message: 'VM configuration updated', vm_id });
    });
  });
});

app.get('/api/vms/:vm_id/stats', checkAuth, async (req, res) => {
  try {
    db.get(`SELECT * FROM vms WHERE vm_id = ?`, [req.params.vm_id], async (err, vm) => {
      if (err || !vm) return res.status(404).json({ error: 'VM not found' });

      const stats = {
        vm_id: vm.vm_id,
        vm_name: vm.vm_name,
        status: vm.status,
        memory: vm.memory,
        cpus: vm.cpus,
        disk_size: vm.disk_size,
        uptime: vm.uptime || 0,
        cpu_usage: 0,
        memory_usage: 0,
        disk_usage: 'N/A',
        pid: vmProcesses.get(vm.vm_id) || null
      };

      if (vm.status === 'running' && vmProcesses.has(vm.vm_id)) {
        const vmDiskPath = vm.vm_disk_path || VM_DIR;
        const pidFile = path.join(vmDiskPath, `vm-${vm.vm_id}.pid`);
        try {
          if (fs.existsSync(pidFile)) {
            const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());
            const { stdout } = await execPromise(`ps -p ${pid} -o %cpu,%mem,etime 2>nul || echo "0 0 0:00"`, { shell: 'cmd' });
            const lines = stdout.trim().split('\n');
            if (lines.length > 0) {
              const data = lines[0].trim().split(/\s+/);
              stats.cpu_usage = parseFloat(data[0]) || 0;
              stats.memory_usage = parseFloat(data[1]) || 0;
            }
          }
        } catch (e) {
          // Silent fail
        }

        if (fs.existsSync(vm.disk_file)) {
          const size = fs.statSync(vm.disk_file).size / (1024 * 1024 * 1024);
          stats.disk_usage = size.toFixed(2) + ' GB';
        }
      }

      res.json(stats);
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// VM REINSTALL ENDPOINT
// ============================================
// POST /api/vms/:vm_id/reinstall
// Owner can reinstall their VM with a different OS template
// Deletes disk and seed ISO but keeps logs
app.post('/api/vms/:vm_id/reinstall', checkAuth, async (req, res) => {
  try {
    const vm_id = req.params.vm_id;
    const { new_os_template, new_username, new_password, confirm } = req.body;
    const userId = req.session.userId;

    if (!confirm) {
      return res.status(400).json({ error: 'Reinstall must be confirmed' });
    }

    if (!new_os_template) {
      return res.status(400).json({ error: 'Please select an OS template' });
    }

    // Get VM
    const getVmQuery = req.session.role === 'admin' 
      ? `SELECT * FROM vms WHERE vm_id = ?`
      : `SELECT * FROM vms WHERE vm_id = ? AND (owner_id = ? OR owner_id IS NULL)`;
    
    const params = req.session.role === 'admin' 
      ? [vm_id]
      : [vm_id, userId];

    db.get(getVmQuery, params, async (err, vm) => {
      if (err || !vm) {
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      // Only allow reinstall if VM is stopped
      if (vm.status !== 'stopped') {
        return res.status(400).json({ error: 'VM must be stopped to reinstall' });
      }

      console.log(`[VM-${vm_id}] ✓ Starting reinstall with template: ${new_os_template}`);
      console.log(`[VM-${vm_id}] Current status: ${vm.status}`);

      try {
        // Validate new template
        let template = null;
        let isCloudInit = false;
        let templateName = 'Custom OS';
        let username = new_username || 'root';
        let password = new_password || 'password';

        if (OS_TEMPLATES[new_os_template]) {
          // Built-in template
          template = OS_TEMPLATES[new_os_template];
          isCloudInit = true;
          templateName = template.name;
          username = new_username || template.username;
          password = new_password || template.password;
          console.log(`[VM-${vm_id}] Using built-in template: ${templateName}`);
        } else {
          // Check database for custom template
          const customTemplate = await new Promise((resolve, reject) => {
            db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [new_os_template], (err, result) => {
              if (err) reject(err);
              else resolve(result);
            });
          });

          if (!customTemplate) {
            const builtInKeys = Object.keys(OS_TEMPLATES);
            return res.status(400).json({ 
              error: `Invalid OS template: ${new_os_template}. Available: ${builtInKeys.join(', ')}` 
            });
          }

          template = customTemplate;
          isCloudInit = customTemplate.template_type === 'cloud-init';
          templateName = customTemplate.template_name;
          username = new_username || customTemplate.username || 'ubuntu';
          password = new_password || customTemplate.password || 'password';
          console.log(`[VM-${vm_id}] Using custom template: ${templateName}`);
        }

        // Delete old files (but keep logs)
        console.log(`[VM-${vm_id}] Cleaning up old files...`);
        
        if (vm.disk_file && fs.existsSync(vm.disk_file)) {
          try {
            fs.unlinkSync(vm.disk_file);
            console.log(`[VM-${vm_id}] ✓ Deleted disk file: ${vm.disk_file}`);
          } catch (err) {
            console.warn(`[VM-${vm_id}] ⚠ Failed to delete disk file:`, err.message);
          }
        }

        if (vm.seed_file && fs.existsSync(vm.seed_file)) {
          try {
            fs.unlinkSync(vm.seed_file);
            console.log(`[VM-${vm_id}] ✓ Deleted seed ISO: ${vm.seed_file}`);
          } catch (err) {
            console.warn(`[VM-${vm_id}] ⚠ Failed to delete seed ISO:`, err.message);
          }
        }

        // NOTE: Keep log files for audit trail

        // Update VM with new template info and credentials
        db.run(
          `UPDATE vms SET 
            os_type = ?, template_type = ?, username = ?, password = ?,
            img_file = '', seed_file = ?, disk_file = ?
          WHERE vm_id = ?`,
          [templateName, new_os_template, username, password, vm.seed_file, vm.disk_file, vm_id],
          async (err) => {
            if (err) {
              console.error(`[VM-${vm_id}] Failed to update VM info:`, err.message);
              return res.status(500).json({ error: 'Failed to update VM: ' + err.message });
            }

            console.log(`[VM-${vm_id}] ✓ VM info updated - template: ${templateName}, user: ${username}`);

            try {
              // Re-download/setup template if cloud-init
              if (isCloudInit) {
                console.log(`[VM-${vm_id}] Preparing cloud-init template...`);

                db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vm_id], async (err, updatedVm) => {
                  if (err || !updatedVm) {
                    console.error(`[VM-${vm_id}] Failed to fetch updated VM`);
                    return;
                  }

                  try {
                    // Handle template download/copy
                    let imgSourcePath = null;

                    if (OS_TEMPLATES[new_os_template]) {
                      // Built-in template - check cache
                      const cachedTemplateName = `${new_os_template}-template.qcow2`;
                      const cachedTemplatePath = path.join(TEMPLATES_DIR, cachedTemplateName);

                      if (fs.existsSync(cachedTemplatePath)) {
                        console.log(`[VM-${vm_id}] ✓ Using cached template: ${cachedTemplatePath}`);
                        imgSourcePath = cachedTemplatePath;
                      } else {
                        // Download template
                        const downloadUrl = OS_TEMPLATES[new_os_template].url;
                        console.log(`[VM-${vm_id}] Downloading template from: ${downloadUrl}`);
                        
                        await downloadTemplate(new_os_template, cachedTemplatePath);
                        imgSourcePath = cachedTemplatePath;
                        console.log(`[VM-${vm_id}] ✓ Template downloaded and cached`);
                      }
                    } else {
                      // Custom template - use local path
                      const customTemplate = await new Promise((resolve, reject) => {
                        db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [new_os_template], (err, result) => {
                          if (err) reject(err);
                          else resolve(result);
                        });
                      });

                      if (customTemplate && customTemplate.local_path && fs.existsSync(customTemplate.local_path)) {
                        imgSourcePath = customTemplate.local_path;
                        console.log(`[VM-${vm_id}] ✓ Using custom template: ${imgSourcePath}`);
                      }
                    }

                    if (!imgSourcePath) {
                      console.error(`[VM-${vm_id}] Failed to locate template`);
                      logVMAction(vm_id, 'reinstall', 'error', 'Failed to locate OS template');
                      return;
                    }

                    // Create new disk from template
                    console.log(`[VM-${vm_id}] Creating new disk from template...`);
                    const diskSizeVal = updatedVm.disk_size || '20G';
                    
                    try {
                      // Copy template to disk file
                      const copyCommand = process.platform === 'win32'
                        ? `Copy-Item -Path "${imgSourcePath}" -Destination "${updatedVm.disk_file}" -Force`
                        : `cp "${imgSourcePath}" "${updatedVm.disk_file}"`;

                      execSync(copyCommand, { shell: process.platform === 'win32' ? 'powershell' : '/bin/bash' });
                      console.log(`[VM-${vm_id}] ✓ Disk file created`);

                      // Resize disk to specified size
                      const resizeCommand = process.platform === 'win32'
                        ? `qemu-img resize "${updatedVm.disk_file}" ${diskSizeVal}`
                        : `qemu-img resize "${updatedVm.disk_file}" ${diskSizeVal}`;

                      execSync(resizeCommand, { stdio: 'pipe' });
                      console.log(`[VM-${vm_id}] ✓ Disk resized to ${diskSizeVal}`);

                      // Create new cloud-init seed
                      console.log(`[VM-${vm_id}] Creating cloud-init seed with new credentials...`);
                      await createCloudInitSeed(vm_id, updatedVm);
                      console.log(`[VM-${vm_id}] ✓ Cloud-init seed created`);

                      // Log the action
                      logVMAction(vm_id, 'reinstall', 'success', 
                        `VM reinstalled with ${templateName}. Old disk and seed deleted. New credentials: ${username} / ****. VM ready to start.`);

                      res.json({ 
                        success: true, 
                        message: `VM ${vm_id} reinstalled successfully with ${templateName}. Ready to start.`,
                        vm_id 
                      });

                    } catch (err) {
                      console.error(`[VM-${vm_id}] Disk creation failed:`, err.message);
                      logVMAction(vm_id, 'reinstall', 'error', `Disk creation failed: ${err.message}`);
                      res.status(500).json({ error: 'Failed to create disk: ' + err.message });
                    }

                  } catch (err) {
                    console.error(`[VM-${vm_id}] Reinstall failed:`, err.message);
                    logVMAction(vm_id, 'reinstall', 'error', `Reinstall failed: ${err.message}`);
                    res.status(500).json({ error: 'Reinstall failed: ' + err.message });
                  }
                });

              } else {
                // Non-cloud-init template (ISO)
                logVMAction(vm_id, 'reinstall', 'success', `VM configuration updated for ${templateName}. Ready to start.`);
                res.json({ 
                  success: true, 
                  message: `VM updated to ${templateName}. Ready to start.`,
                  vm_id 
                });
              }

            } catch (err) {
              console.error(`[VM-${vm_id}] Post-reinstall processing failed:`, err.message);
              logVMAction(vm_id, 'reinstall', 'error', `Post-reinstall processing failed: ${err.message}`);
              res.status(500).json({ error: 'Post-reinstall processing failed: ' + err.message });
            }
          }
        );

      } catch (err) {
        console.error(`[VM-${vm_id}] Reinstall error:`, err.message);
        logVMAction(vm_id, 'reinstall', 'error', err.message);
        res.status(500).json({ error: 'Reinstall failed: ' + err.message });
      }
    });

  } catch (err) {
    console.error(`Reinstall endpoint error:`, err.message);
    res.status(500).json({ error: err.message });
  }
});

// VM CREATE (Admin only)
app.post('/api/vms', checkAuth, checkAdmin, async (req, res) => {
  const { 
    vm_name, os_template, hostname, custom_memory, custom_cpus,
    iso_file, custom_username, custom_password, disk_size,
    cpu_sockets, cpu_cores, cpu_threads, cpu_model, custom_cpu_name,
    machine_type, board_name, product_name, custom_smbios_manufacturer,
    smbios_manufacturer, smbios_product, smbios_version, smbios_serial,
    enable_acpi, enable_kvm, extra_args,
    network_type, ipv4_address, gateway, netmask, bridge_device,
    dns_servers, ssh_port, ssh_port_static, http_port,
    ipv6_address, ipv6_gateway, mac_address, vlan_id, owner_id,
    vm_disk_path, iso_path
  } = req.body;
  
  // Alias gateway to ipv4_gateway for consistency
  const ipv4_gateway = gateway;
  const ipv4_netmask = netmask;
  // Parse DNS servers - can be comma-separated
  const dns_list = dns_servers ? dns_servers.split(',').map(d => d.trim()) : ['8.8.8.8', '8.8.4.4'];
  const dns_primary = dns_list[0] || '8.8.8.8';
  const dns_secondary = dns_list[1] || '8.8.4.4';
  
  // Either os_template or iso_file must be provided
  if (!os_template && !iso_file) {
    return res.status(400).json({ error: 'Please select a template or upload ISO' });
  }

  // Validate memory - remove strict limits, allow any positive value
  const memoryNum = parseInt(custom_memory);
  if (!memoryNum || memoryNum < 1) {
    return res.status(400).json({ error: 'Memory must be at least 1 MB' });
  }

  // Validate CPUs - remove strict limits, allow any positive value
  const cpusNum = parseInt(custom_cpus);
  if (!cpusNum || cpusNum < 1) {
    return res.status(400).json({ error: 'CPUs must be at least 1' });
  }

  // Validate bridge device if using static IP
  if (network_type === 'static_public' && bridge_device) {
    if (!/^[a-z0-9]+$/.test(bridge_device)) {
      return res.status(400).json({ error: 'Invalid bridge device name. Use only lowercase letters and numbers (e.g., vmbr0, vmbr1)' });
    }
  }

  let template = null;
  let isCloudInit = false;
  let templateName = 'Custom ISO';
  let username = custom_username || 'root';
  let password = custom_password || 'password';

  if (os_template) {
    // Check if it's a built-in template
    if (OS_TEMPLATES[os_template]) {
      template = OS_TEMPLATES[os_template];
      isCloudInit = true;
      templateName = template.name;
      username = custom_username || template.username;
      password = custom_password || template.password;
    } else {
      // Not built-in, check database for custom template
      const customTemplate = await new Promise((resolve, reject) => {
        db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [os_template], (err, result) => {
          if (err) reject(err);
          else resolve(result);
        });
      });

      if (!customTemplate) {
        const builtInKeys = Object.keys(OS_TEMPLATES);
        console.warn(`[VM Creation] Invalid template key: "${os_template}". Available built-in: ${builtInKeys.join(', ')}`);
        return res.status(400).json({ error: `Invalid OS template: ${os_template}. Please select a valid template.` });
      }

      // Use custom template
      template = customTemplate;
      isCloudInit = customTemplate.template_type === 'cloud-init';
      templateName = customTemplate.template_name;
      username = custom_username || customTemplate.username || 'ubuntu';
      password = custom_password || customTemplate.password || 'password';
      console.log(`[VM Creation] Using custom template: ${templateName} (${os_template})`);
    }
  }

  const memory = parseInt(custom_memory) || (template ? template.memory : 2048);
  const cpuCount = parseInt(custom_cpus) || (template ? template.cpus : 2);
  const sockets = cpu_sockets || 1;
  const cores = cpu_cores || cpuCount;
  const threads = cpu_threads || 1;
  const cpuModelToUse = cpu_model && CPU_MODELS[cpu_model] ? cpu_model : 'host';
  const diskSizeVal = disk_size || (template ? template.disk_size : '20G');
  const netType = network_type || 'nat';
  const macAddr = mac_address || generateMACAddress();
  const vmOwner = owner_id || req.session.userId; // Use selected owner if provided, else current user
  
  // Handle SSH port - prefer ssh_port_static if provided, else use ssh_port
  const sshPortVal = ssh_port_static || ssh_port || 22;
  
  // Insert VM first to get vm_id
  db.run(
    `INSERT INTO vms (
      vm_name, os_type, template_type, hostname, username, password, 
      memory, cpus, cpu_sockets, cpu_cores, cpu_threads, cpu_model, custom_cpu_name,
      machine_type, board_name, product_name, custom_smbios_manufacturer,
      disk_size, img_file, seed_file, disk_file,
      status, uptime, node_name,
      smbios_manufacturer, smbios_product, smbios_version, smbios_serial,
      extra_args, enable_acpi, enable_kvm,
      network_type, ipv4_address, ipv4_gateway, ipv4_netmask,
      dns_servers, dns_primary, dns_secondary, ssh_port, ssh_port_static, http_port,
      ipv6_address, ipv6_gateway, mac_address, bridge_device, vlan_id, owner_id,
      vm_disk_path, iso_path
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      vm_name, templateName, os_template || (isCloudInit ? 'cloud-init' : 'iso-installer'), hostname, 
      username, password, memory, cpuCount, sockets, cores, threads, cpuModelToUse, custom_cpu_name || null,
      machine_type || 'pc', board_name || 'Main-Board', product_name || 'Virtual Machine', custom_smbios_manufacturer || 'QEMU',
      diskSizeVal, '', '', '',
      'stopped', 0, 'localhost',
      smbios_manufacturer || 'QEMU', smbios_product || 'KVM Virtual Machine',
      smbios_version || '1.0', smbios_serial || `vm-${Date.now()}`,
      extra_args || '', enable_acpi !== false ? 1 : 0, enable_kvm !== false ? 1 : 0,
      netType, ipv4_address || null, ipv4_gateway || null, ipv4_netmask || '255.255.255.0',
      dns_servers || '8.8.8.8,8.8.4.4', dns_primary || '8.8.8.8', dns_secondary || '8.8.4.4', null, sshPortVal, http_port || 80,
      ipv6_address || null, ipv6_gateway || null,
      macAddr, bridge_device || 'vmbr0', vlan_id || null, vmOwner,
      vm_disk_path || VM_DIR, iso_path || CLOUDVM_DIR
    ],
    async function(err) {
      if (err) return res.status(500).json({ error: err.message });
      
      const vm_id = this.lastID;
      
      // Use custom paths if provided, otherwise use defaults
      const baseDiskPath = (vm_disk_path && vm_disk_path.trim()) ? vm_disk_path.trim() : VM_DIR;
      const baseIsoPath = (iso_path && iso_path.trim()) ? iso_path.trim() : CLOUDVM_DIR;
      
      // Validate paths are absolute
      if (!baseDiskPath.startsWith('/') || !baseIsoPath.startsWith('/')) {
        db.run(`DELETE FROM vms WHERE vm_id = ?`, [vm_id]);
        console.error(`[VM Creation] Invalid paths - must be absolute: disk=${baseDiskPath}, iso=${baseIsoPath}`);
        return res.status(400).json({ error: 'Storage paths must be absolute paths (starting with /)' });
      }
      
      // Ensure directories exist
      try {
        if (!fs.existsSync(baseDiskPath)) {
          fs.mkdirSync(baseDiskPath, { recursive: true });
          console.log(`[VM Creation] Created disk directory: ${baseDiskPath}`);
        }
        if (!fs.existsSync(baseIsoPath)) {
          fs.mkdirSync(baseIsoPath, { recursive: true });
          console.log(`[VM Creation] Created ISO directory: ${baseIsoPath}`);
        }
      } catch (mkErr) {
        db.run(`DELETE FROM vms WHERE vm_id = ?`, [vm_id]);
        console.error(`[VM Creation] Failed to create directories: ${mkErr.message}`);
        return res.status(500).json({ error: `Failed to create storage directories: ${mkErr.message}` });
      }
      
      // Cloud-init images go to ISO path, regular disks go to disk path
      const img_file = isCloudInit 
        ? path.join(baseIsoPath, `${os_template || 'custom'}-${vm_id}.qcow2`)
        : path.join(baseIsoPath, `${os_template || 'custom'}-${vm_id}.qcow2`);
      const disk_file = path.join(baseDiskPath, `vm-${vm_id}-disk.qcow2`);
      const seed_file = path.join(baseDiskPath, `vm-${vm_id}-seed.iso`);

      try {
        // Update with file paths
        db.run(
          `UPDATE vms SET img_file = ?, seed_file = ?, disk_file = ? WHERE vm_id = ?`,
          [img_file, seed_file, disk_file, vm_id],
          async (err) => {
            if (err) {
              db.run(`DELETE FROM vms WHERE vm_id = ?`, [vm_id]);
              return res.status(500).json({ error: err.message });
            }

            console.log(`[VM-${vm_id}] ✓ Updated database with file paths`);
            console.log(`[VM-${vm_id}] disk_file = ${disk_file}`);
            console.log(`[VM-${vm_id}] seed_file = ${seed_file}`);
            console.log(`[VM-${vm_id}] img_file = ${img_file}`);
            console.log(`[VM-${vm_id}] vm_disk_path = ${baseDiskPath}`);

            try {
              // If using cloud-init template, check cache first
              if (os_template && isCloudInit) {
                console.log(`[VM-${vm_id}] Created with custom paths: disk_path="${baseDiskPath}", iso_path="${baseIsoPath}"`);
                console.log(`[VM-${vm_id}] File paths: disk="${disk_file}", seed="${seed_file}", img="${img_file}"`);
                // Check if it's a built-in or custom template
                let templateSourcePath = null;

                if (OS_TEMPLATES[os_template]) {
                  // Built-in template - use cache in /vms/templates
                  const cachedTemplateName = `${os_template}-template.qcow2`;
                  const cachedTemplatePath = path.join(TEMPLATES_DIR, cachedTemplateName);

                  if (fs.existsSync(cachedTemplatePath)) {
                    console.log(`[VM-${vm_id}] Using cached built-in template from: ${cachedTemplatePath}`);
                    templateSourcePath = cachedTemplatePath;
                  } else {
                    console.log(`[VM-${vm_id}] Cached template not found at ${cachedTemplatePath}`);
                    console.log(`[VM-${vm_id}] Downloading built-in template: ${templateName} to cache...`);
                    
                    // Download to cache first
                    try {
                      await downloadTemplate(os_template, cachedTemplatePath);
                      console.log(`[VM-${vm_id}] ✓ Built-in template cached to: ${cachedTemplatePath}`);
                      templateSourcePath = cachedTemplatePath;
                    } catch (dlErr) {
                      console.error(`[VM-${vm_id}] Template download failed:`, dlErr.message);
                      throw new Error(`Failed to download built-in template: ${dlErr.message}`);
                    }
                  }
                } else {
                  // Custom template - check database for local path
                  const customTemplate = await new Promise((resolve, reject) => {
                    db.get(`SELECT * FROM os_templates WHERE template_key = ?`, [os_template], (err, result) => {
                      if (err) reject(err);
                      else resolve(result);
                    });
                  });

                  if (!customTemplate) {
                    throw new Error(`Custom template "${os_template}" not found in database`);
                  }

                  if (customTemplate.local_path && fs.existsSync(customTemplate.local_path)) {
                    console.log(`[VM-${vm_id}] Using cached custom template from: ${customTemplate.local_path}`);
                    templateSourcePath = customTemplate.local_path;
                  } else if (customTemplate.download_url) {
                    console.log(`[VM-${vm_id}] Custom template not cached, downloading from ${customTemplate.download_url}...`);
                    
                    // Generate local path if not set
                    let localPath = customTemplate.local_path;
                    if (!localPath) {
                      const urlParts = customTemplate.download_url.split('/');
                      const fileName = urlParts[urlParts.length - 1] || `${os_template}-template.qcow2`;
                      localPath = path.join(TEMPLATES_DIR, fileName);
                    }

                    try {
                      // Create templates directory if needed
                      if (!fs.existsSync(TEMPLATES_DIR)) {
                        fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
                      }

                      await downloadTemplateFromURL(customTemplate.download_url, localPath);
                      console.log(`[VM-${vm_id}] ✓ Custom template downloaded to: ${localPath}`);
                      
                      // Update database with local path
                      await new Promise((resolve, reject) => {
                        db.run(`UPDATE os_templates SET local_path = ? WHERE template_key = ?`,
                          [localPath, os_template],
                          (err) => {
                            if (err) {
                              console.error('Failed to update template path in DB:', err);
                              reject(err);
                            } else {
                              resolve();
                            }
                          }
                        );
                      });

                      templateSourcePath = localPath;
                    } catch (dlErr) {
                      console.error(`[VM-${vm_id}] Custom template download failed:`, dlErr.message);
                      throw new Error(`Failed to download custom template: ${dlErr.message}`);
                    }
                  } else {
                    throw new Error(`Custom template "${os_template}" has no local path or download URL`);
                  }
                }

                // Copy template to VM's image file
                if (templateSourcePath) {
                  try {
                    const copyCmd = process.platform === 'win32' 
                      ? `copy "${templateSourcePath}" "${img_file}"`
                      : `cp "${templateSourcePath}" "${img_file}"`;
                    
                    console.log(`[VM-${vm_id}] Copying template to: ${img_file}`);
                    await execPromise(copyCmd, { 
                      shell: process.platform === 'win32' ? 'cmd' : '/bin/bash',
                      stdio: 'pipe'
                    });
                    console.log(`[VM-${vm_id}] ✓ Copied template to ${img_file}`);
                  } catch (copyErr) {
                    console.error(`[VM-${vm_id}] Failed to copy template:`, copyErr.message);
                    throw new Error(`Failed to copy template: ${copyErr.message}`);
                  }
                }
              }

              // Create cloud-init seed if cloud-init type
              if (isCloudInit) {
                const vmData = {
                  vm_id,
                  vm_name,
                  hostname,
                  username,
                  password,
                  network_type: netType,
                  ipv4_address: ipv4_address || null,
                  ipv4_gateway: ipv4_gateway || null,
                  ipv4_netmask: ipv4_netmask || '255.255.255.0',
                  dns_primary: dns_primary || '8.8.8.8',
                  dns_secondary: dns_secondary || '8.8.4.4',
                  ipv6_address: ipv6_address || null,
                  ipv6_gateway: ipv6_gateway || null
                };
                await createCloudInitSeed(vm_id, vmData);
                
                // Create disk from template with resize to specified size
                console.log(`[VM-${vm_id}] Creating and resizing disk to ${diskSizeVal}...`);
                try {
                  // Copy template to disk file and resize in one step
                  const resizeDiskCmd = `qemu-img convert -O qcow2 "${img_file}" "${disk_file}" && qemu-img resize "${disk_file}" ${diskSizeVal}`;
                  await execPromise(resizeDiskCmd, { 
                    shell: isWindows ? 'cmd' : '/bin/bash',
                    stdio: 'pipe'
                  });
                  
                  console.log(`[VM-${vm_id}] ✓ Disk created and resized to: ${diskSizeVal}`);
                } catch (diskError) {
                  logError('DISK', vm_id, 'creation', diskError);
                  throw new Error(`Disk creation failed: ${diskError.message}`);
                }
              } else {
                // ISO mode: Create a new disk from scratch with specified size
                console.log(`[VM-${vm_id}] Creating disk: ${disk_file} (size: ${diskSizeVal})`);
                try {
                  const createDiskCmd = `qemu-img create -f qcow2 "${disk_file}" ${diskSizeVal}`;
                  
                  await execPromise(createDiskCmd, { 
                    shell: isWindows ? 'cmd' : '/bin/bash',
                    stdio: 'pipe'
                  });
                  console.log(`[VM-${vm_id}] ✓ Disk created: ${diskSizeVal}`);
                } catch (diskError) {
                  logError('DISK', vm_id, 'creation', diskError);
                  throw new Error(`Disk creation failed: ${diskError.message}`);
                }
              }

              logVMAction(vm_id, 'create', 'pending', `VM ${vm_name} (ID:${vm_id}) created from ${templateName}`);
              res.json({ 
                success: true, 
                vm_id: vm_id, 
                template: isCloudInit ? 'cloud-init' : 'iso-installer',
                config: {
                  cpus: cpuCount,
                  sockets: sockets,
                  cores: cores,
                  threads: threads,
                  cpu_model: cpuModelToUse,
                  memory: memory,
                  disk_size: diskSizeVal,
                  network_type: netType,
                  mac_address: macAddr,
                  ipv4: ipv4_address,
                  gateway: ipv4_gateway
                }
              });
            } catch (downloadError) {
              logError('TEMPLATE', vm_id, 'download', downloadError);
              // Clean up partial files
              if (fs.existsSync(img_file)) {
                try { fs.unlinkSync(img_file); } catch (e) {}
              }
              db.run(`DELETE FROM vms WHERE vm_id = ?`, [vm_id]);
              return res.status(500).json({ error: `Failed to download template: ${downloadError.message}` });
            }
          }
        );
      } catch (error) {
        logError('VM', vm_id, 'outer', error);
        res.status(500).json({ error: error.message });
      }
    }
  );
});

// VM START (Using VM ID)
app.post('/api/vms/:vm_id/start', checkAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    let query = `SELECT * FROM vms WHERE vm_id = ?`;
    let params = [req.params.vm_id];
    
    // Normal users can only start their own VMs
    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }
    
    db.get(query, params, async (err, vm) => {
      if (err || !vm) {
        console.error(`[API Error] /api/vms/${req.params.vm_id}/start: VM not found or access denied`);
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      if (vm.status === 'running') {
        console.log(`[API] VM ${vm.vm_id} already running`);
        return res.json({ success: true, message: `VM ${vm.vm_name} is already running` });
      }

      try {
        console.log(`[API] Starting VM ${vm.vm_id} (${vm.vm_name}) by user ${userId}`);
        const result = await startQemuVM(vm);
        if (result.success) {
          vmProcesses.set(vm.vm_id, result.pid);
          db.run(`UPDATE vms SET status = 'running', uptime = 0 WHERE vm_id = ?`, [vm.vm_id]);
          logVMAction(vm.vm_id, 'start', 'running', `VM started successfully`);
          console.log(`[API Success] VM ${vm.vm_id} started successfully`);
          res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) started`, vm_id: vm.vm_id });
        } else {
          console.error(`[API Error] Failed to start VM ${vm.vm_id}`);
          res.status(500).json({ error: 'Failed to start VM' });
        }
      } catch (error) {
        console.error(`[API Error] Exception starting VM ${vm.vm_id}:`, error);
        logVMAction(vm.vm_id, 'start', 'failed', error.message);
        res.status(500).json({ error: error.message });
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VM STOP (Using VM ID)
app.post('/api/vms/:vm_id/stop', checkAuth, (req, res) => {
  const userId = req.session.userId;
  let query = `SELECT * FROM vms WHERE vm_id = ?`;
  let params = [req.params.vm_id];
  
  // Normal users can only stop their own VMs
  if (req.session.role !== 'admin') {
    query += ` AND owner_id = ?`;
    params.push(userId);
  }
  
  db.get(query, params, (err, vm) => {
    if (err || !vm) {
      console.error(`[API Error] /api/vms/${req.params.vm_id}/stop: VM not found or access denied`);
      return res.status(404).json({ error: 'VM not found or access denied' });
    }

    if (vm.status === 'stopped') {
      console.log(`[API] VM ${vm.vm_id} already stopped`);
      return res.json({ success: true, message: 'VM already stopped' });
    }

    try {
      console.log(`[API] Stopping VM ${vm.vm_id} (${vm.vm_name}) by user ${userId}`);
      const vmDiskPath = vm.vm_disk_path || VM_DIR;
      const pidFile = path.join(vmDiskPath, `vm-${vm.vm_id}.pid`);
      if (fs.existsSync(pidFile)) {
        const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());
        try {
          // On Windows, use taskkill; on Unix, use process group kill
          if (isWindows) {
            exec(`taskkill /F /PID ${pid}`, { shell: 'cmd' });
          } else {
            // Kill entire process group (- prefix means pgid)
            process.kill(-pid, 'SIGTERM');
            setTimeout(() => {
              try {
                process.kill(-pid, 'SIGKILL');
              } catch (e) {}
            }, 3000);
          }
        } catch (e) {
          // Process may already be dead
        }
      }

      vmProcesses.delete(vm.vm_id);
      db.run(`UPDATE vms SET status = 'stopped' WHERE vm_id = ?`, [vm.vm_id]);
      logVMAction(vm.vm_id, 'stop', 'stopped', `VM stopped`);
      console.log(`[API Success] VM ${vm.vm_id} stopped successfully`);
      res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) stopped` });
    } catch (error) {
      console.error(`[API Error] Exception stopping VM ${vm.vm_id}:`, error);
      res.status(500).json({ error: error.message });
    }
  });
});

// VM RESTART (Using VM ID)
app.post('/api/vms/:vm_id/restart', checkAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    let query = `SELECT * FROM vms WHERE vm_id = ?`;
    let params = [req.params.vm_id];
    
    // Normal users can only restart their own VMs
    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }
    
    db.get(query, params, async (err, vm) => {
      if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });

      try {
        const vmDiskPath = vm.vm_disk_path || VM_DIR;
        const pidFile = path.join(vmDiskPath, `vm-${vm.vm_id}.pid`);
        if (fs.existsSync(pidFile)) {
          const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());
          try {
            process.kill(pid, 'SIGTERM');
          } catch (e) {}
        }
        
        await new Promise(resolve => setTimeout(resolve, 2000));

        const result = await startQemuVM(vm);
        if (result.success) {
          vmProcesses.set(vm.vm_id, result.pid);
          db.run(`UPDATE vms SET status = 'running' WHERE vm_id = ?`, [vm.vm_id]);
          logVMAction(vm.vm_id, 'restart', 'running', `VM restarted successfully`);
          res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) restarted` });
        } else {
          res.status(500).json({ error: 'Failed to restart VM' });
        }
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VM REINSTALL (Using VM ID)

// VM DELETE (Using VM ID)
app.delete('/api/vms/:vm_id', checkAuth, (req, res) => {
  db.get(`SELECT * FROM vms WHERE vm_id = ?`, [req.params.vm_id], (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found' });

    try {
      // Use custom disk path from VM record, fallback to VM_DIR
      const vmDiskPath = vm.vm_disk_path || VM_DIR;
      
      // Kill process if running
      const pidFile = path.join(vmDiskPath, `vm-${vm.vm_id}.pid`);
      if (fs.existsSync(pidFile)) {
        try {
          const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());
          process.kill(pid, 'SIGKILL');
        } catch (e) {}
      }

      // Delete all VM files
      const logFile = path.join(vmDiskPath, `vm-${vm.vm_id}.log`);
      const files = [
        vm.img_file,
        vm.seed_file,
        vm.disk_file,
        pidFile,
        logFile
      ];

      files.forEach(file => {
        if (file && fs.existsSync(file)) {
          try {
            fs.unlinkSync(file);
            console.log(`[VM-${vm.vm_id}] ✓ Deleted file: ${file}`);
          } catch (e) {
            console.warn(`[VM-${vm.vm_id}] Warning: Could not delete ${file}: ${e.message}`);
          }
        }
      });

      // Delete database records
      vmProcesses.delete(vm.vm_id);
      db.run(`DELETE FROM vms WHERE vm_id = ?`, [vm.vm_id]);
      db.run(`DELETE FROM vm_logs WHERE vm_id = ?`, [vm.vm_id]);
      
      logVMAction(vm.vm_id, 'delete', 'deleted', `VM ${vm.vm_name} deleted`);
      console.log(`[VM-${vm.vm_id}] ✓ VM completely deleted: ${vm.vm_name}`);
      res.json({ success: true, message: `VM ${vm.vm_name} (ID:${vm.vm_id}) deleted` });
    } catch (error) {
      console.error(`[VM-${req.params.vm_id}] Delete error:`, error.message);
      res.status(500).json({ error: error.message });
    }
  });
});

// VM LOGS (Using VM ID)
app.get('/api/vms/:vm_id/logs', checkAuth, (req, res) => {
  db.all(
    `SELECT * FROM vm_logs WHERE vm_id = ? ORDER BY timestamp DESC LIMIT 50`,
    [req.params.vm_id],
    (err, logs) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(logs || []);
    }
  );
});

// VM SNAPSHOTS (Using VM ID)
app.get('/api/vms/:vm_id/snapshots', checkAuth, (req, res) => {
  const userId = req.session.userId;
  let query = `SELECT * FROM vm_snapshots WHERE vm_id = ?`;
  let params = [req.params.vm_id];
  
  // First check ownership if not admin
  if (req.session.role !== 'admin') {
    // Check if user owns this VM
    db.get(`SELECT * FROM vms WHERE vm_id = ? AND owner_id = ?`, [req.params.vm_id, userId], (err, vm) => {
      if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });
      
      db.all(query, params, (err, snapshots) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(snapshots || []);
      });
    });
  } else {
    db.all(query, params, (err, snapshots) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(snapshots || []);
    });
  }
});

// ============= ISO ATTACH/DETACH ENDPOINTS =============

// Attach ISO to VM (for ISO templates or manual ISO installation)
app.post('/api/vms/:vm_id/iso/attach', checkAuth, async (req, res) => {
  try {
    const vm_id = req.params.vm_id;
    const { iso_file } = req.body;
    const userId = req.session.userId;

    if (!iso_file) {
      return res.status(400).json({ error: 'ISO file is required' });
    }

    // Get VM
    let query = `SELECT * FROM vms WHERE vm_id = ?`;
    let params = [vm_id];

    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }

    db.get(query, params, (err, vm) => {
      if (err || !vm) {
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      // Verify ISO file exists
      const isoPath = path.join(ISO_DIR, iso_file);
      if (!fs.existsSync(isoPath)) {
        return res.status(400).json({ error: 'ISO file not found' });
      }

      // Update VM with attached ISO
      db.run(
        `UPDATE vms SET iso_attached = ?, boot_from_iso = 1 WHERE vm_id = ?`,
        [iso_file, vm_id],
        (err) => {
          if (err) {
            return res.status(500).json({ error: err.message });
          }

          logVMAction(vm_id, 'iso_attach', 'completed', `ISO file attached: ${iso_file}`);
          res.json({ success: true, message: `ISO file "${iso_file}" attached successfully` });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Detach ISO from VM
app.post('/api/vms/:vm_id/iso/detach', checkAuth, async (req, res) => {
  try {
    const vm_id = req.params.vm_id;
    const userId = req.session.userId;

    // Get VM
    let query = `SELECT * FROM vms WHERE vm_id = ?`;
    let params = [vm_id];

    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }

    db.get(query, params, (err, vm) => {
      if (err || !vm) {
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      // Update VM to remove attached ISO and boot from disk
      db.run(
        `UPDATE vms SET iso_attached = NULL, boot_from_iso = 0 WHERE vm_id = ?`,
        [vm_id],
        (err) => {
          if (err) {
            return res.status(500).json({ error: err.message });
          }

          logVMAction(vm_id, 'iso_detach', 'completed', 'ISO file detached, will boot from disk');
          res.json({ success: true, message: 'ISO file detached successfully' });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get VM ISO status
app.get('/api/vms/:vm_id/iso/status', checkAuth, async (req, res) => {
  try {
    const vm_id = req.params.vm_id;
    const userId = req.session.userId;

    let query = `SELECT vm_id, iso_attached, boot_from_iso, status FROM vms WHERE vm_id = ?`;
    let params = [vm_id];

    if (req.session.role !== 'admin') {
      query += ` AND owner_id = ?`;
      params.push(userId);
    }

    db.get(query, params, (err, vm) => {
      if (err || !vm) {
        return res.status(404).json({ error: 'VM not found or access denied' });
      }

      res.json({
        vm_id: vm.vm_id,
        iso_attached: vm.iso_attached || null,
        boot_from_iso: vm.boot_from_iso ? true : false,
        vm_status: vm.status
      });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/vms/:vm_id/snapshots', checkAuth, (req, res) => {
  const userId = req.session.userId;
  const { snapshot_name, description } = req.body;
  
  let query = `SELECT * FROM vms WHERE vm_id = ?`;
  let params = [req.params.vm_id];
  
  // Normal users can only create snapshots for their own VMs
  if (req.session.role !== 'admin') {
    query += ` AND owner_id = ?`;
    params.push(userId);
  }
  
  db.get(query, params, (err, vm) => {
    if (err || !vm) return res.status(404).json({ error: 'VM not found or access denied' });
    
    db.run(
      `INSERT INTO vm_snapshots (vm_id, snapshot_name, size_gb, description) VALUES (?, ?, 0, ?)`,
      [req.params.vm_id, snapshot_name, description],
      function(err) {
        if (err) return res.status(500).json({ error: err.message });
        logVMAction(req.params.vm_id, 'snapshot', 'completed', `Snapshot ${snapshot_name} created`);
        res.json({ success: true, snapshot_id: this.lastID });
      }
    );
  });
});

// ADMIN DASHBOARD
app.get('/api/admin/dashboard', checkAuth, checkAdmin, (req, res) => {
  db.all(`SELECT COUNT(*) as total FROM users`, (err, userCount) => {
    db.all(`SELECT COUNT(*) as total FROM vms`, (err, vmCount) => {
      db.all(`SELECT COUNT(*) as total FROM vms WHERE status = 'running'`, (err, runningCount) => {
        res.json({
          totalUsers: userCount ? userCount[0].total : 0,
          totalVMs: vmCount ? vmCount[0].total : 0,
          runningVMs: runningCount ? runningCount[0].total : 0
        });
      });
    });
  });
});

// Get recent activity (admin only)
app.get('/api/admin/activity', checkAuth, checkAdmin, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 10, 100);
  
  db.all(
    `SELECT 
      l.id, 
      l.vm_id, 
      l.action, 
      l.status, 
      l.message, 
      l.timestamp,
      v.vm_name
    FROM vm_logs l
    LEFT JOIN vms v ON l.vm_id = v.vm_id
    ORDER BY l.timestamp DESC
    LIMIT ?`,
    [limit],
    (err, logs) => {
      if (err) {
        console.error('[API] Error fetching activity logs:', err);
        return res.status(500).json({ error: err.message });
      }
      
      // Transform logs to activity format
      const activities = (logs || []).map(log => ({
        id: log.id,
        vm_id: log.vm_id,
        vm_name: log.vm_name || 'Unknown VM',
        action: log.action,
        message: log.message || `VM ${log.action} ${log.status || ''}`,
        status: log.status || 'unknown',
        timestamp: log.timestamp
      }));
      
      res.json(activities);
    }
  );
});

// HELPER FUNCTIONS

function logVMAction(vm_id, action, status, message) {
  db.run(
    `INSERT INTO vm_logs (vm_id, action, status, message) VALUES (?, ?, ?, ?)`,
    [vm_id, action, status, message]
  );
}

// Download template with streaming progress to response object
async function downloadTemplateWithStreamingProgress(url, targetPath, res) {
  return new Promise((resolve, reject) => {
    console.log(`[TEMPLATE] Streaming download from URL: ${url}`);

    // Ensure parent directory exists
    const targetDir = path.dirname(targetPath);
    if (!fs.existsSync(targetDir)) {
      try {
        fs.mkdirSync(targetDir, { recursive: true });
        console.log(`[TEMPLATE] Created directory: ${targetDir}`);
      } catch (err) {
        console.error(`[TEMPLATE] Failed to create directory ${targetDir}:`, err.message);
        return reject(new Error(`Cannot create directory: ${err.message}`));
      }
    }

    const file = fs.createWriteStream(targetPath);
    const https = url.startsWith('https') ? require('https') : require('http');
    
    const makeRequest = (currentUrl, redirectCount = 0) => {
      // Limit redirects to prevent infinite loops
      if (redirectCount > 5) {
        fs.unlink(targetPath, () => {});
        return reject(new Error('Too many redirects'));
      }

      https.get(currentUrl, (response) => {
        // Handle redirects (301, 302, 303, 307, 308)
        if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
          const redirectUrl = response.headers.location;
          if (!redirectUrl) {
            fs.unlink(targetPath, () => {});
            return reject(new Error(`Redirect without location header`));
          }
          console.log(`[TEMPLATE] Redirect (${response.statusCode}) to: ${redirectUrl}`);
          return makeRequest(redirectUrl, redirectCount + 1);
        }

        if (response.statusCode !== 200) {
          fs.unlink(targetPath, () => {});
          return reject(new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`));
        }

        const contentLength = parseInt(response.headers['content-length'], 10);
        
        // Send content-length header to frontend for progress calculation
        if (contentLength && !res.headersSent) {
          res.setHeader('Content-Length', contentLength.toString());
          res.setHeader('Content-Type', 'application/octet-stream');
        }

        let downloaded = 0;
        const startTime = Date.now();

        response.on('data', (chunk) => {
          downloaded += chunk.length;
          if (contentLength) {
            const percent = ((downloaded / contentLength) * 100).toFixed(2);
            const elapsed = (Date.now() - startTime) / 1000;
            const speed = elapsed > 0 ? downloaded / elapsed : 0;
            console.log(`[TEMPLATE] Stream progress: ${percent}% (${(downloaded / (1024*1024)).toFixed(1)}MB / ${(contentLength / (1024*1024)).toFixed(1)}MB) @ ${(speed / (1024*1024)).toFixed(1)} MB/s`);
          }
        });

        response.pipe(file);
        response.pipe(res);

        file.on('finish', () => {
          file.close();
          console.log(`[TEMPLATE] Downloaded successfully to ${targetPath}`);
          if (!res.writableEnded) {
            res.end();
          }
          resolve(true);
        });

        file.on('error', (err) => {
          fs.unlink(targetPath, () => {});
          if (!res.writableEnded) {
            res.status(500).end();
          }
          reject(err);
        });

        response.on('error', (err) => {
          fs.unlink(targetPath, () => {});
          if (!res.writableEnded) {
            res.status(500).end();
          }
          reject(err);
        });
      }).on('error', (err) => {
        fs.unlink(targetPath, () => {});
        if (!res.writableEnded) {
          res.status(500).end();
        }
        reject(err);
      });
    };

    makeRequest(url);
  });
}

// Download OS template image
// Download template from URL with redirect support
async function downloadTemplateFromURL(url, targetPath) {
  return new Promise((resolve, reject) => {
    console.log(`[TEMPLATE] Downloading from URL: ${url}`);

    // Ensure parent directory exists
    const targetDir = path.dirname(targetPath);
    if (!fs.existsSync(targetDir)) {
      try {
        fs.mkdirSync(targetDir, { recursive: true });
        console.log(`[TEMPLATE] Created directory: ${targetDir}`);
      } catch (err) {
        console.error(`[TEMPLATE] Failed to create directory ${targetDir}:`, err.message);
        return reject(new Error(`Cannot create directory: ${err.message}`));
      }
    }

    const file = fs.createWriteStream(targetPath);
    const https = url.startsWith('https') ? require('https') : require('http');
    
    const makeRequest = (currentUrl, redirectCount = 0) => {
      // Limit redirects to prevent infinite loops
      if (redirectCount > 5) {
        fs.unlink(targetPath, () => {});
        return reject(new Error('Too many redirects'));
      }

      https.get(currentUrl, (response) => {
        // Handle redirects (301, 302, 303, 307, 308)
        if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
          const redirectUrl = response.headers.location;
          if (!redirectUrl) {
            fs.unlink(targetPath, () => {});
            return reject(new Error(`Redirect without location header`));
          }
          console.log(`[TEMPLATE] Redirect (${response.statusCode}) to: ${redirectUrl}`);
          return makeRequest(redirectUrl, redirectCount + 1);
        }

        if (response.statusCode !== 200) {
          fs.unlink(targetPath, () => {});
          return reject(new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`));
        }

        const len = parseInt(response.headers['content-length'], 10);
        let downloaded = 0;

        response.on('data', (chunk) => {
          downloaded += chunk.length;
          if (len) {
            const percent = ((downloaded / len) * 100).toFixed(2);
            console.log(`[TEMPLATE] Download progress: ${percent}%`);
          }
        });

        response.pipe(file);
        file.on('finish', () => {
          file.close();
          console.log(`[TEMPLATE] Downloaded successfully`);
          resolve(true);
        });
        file.on('error', (err) => {
          fs.unlink(targetPath, () => {});
          reject(err);
        });
      }).on('error', (err) => {
        fs.unlink(targetPath, () => {});
        reject(err);
      });
    };

    makeRequest(url);
  });
}

// Download OS template from built-in templates OR directly from URL
async function downloadTemplate(sourceOrKey, targetPath) {
  return new Promise(async (resolve, reject) => {
    try {
      let url;
      let templateName;

      // Check if it's a template key or a direct URL
      if (OS_TEMPLATES[sourceOrKey]) {
        const template = OS_TEMPLATES[sourceOrKey];
        url = template.url;
        templateName = template.name;
      } else if (sourceOrKey.startsWith('http')) {
        // It's a direct URL
        url = sourceOrKey;
        templateName = 'custom template';
      } else {
        return reject(new Error('Invalid template key or URL'));
      }

      console.log(`[TEMPLATE] Downloading ${templateName} from ${url}...`);

      await downloadTemplateFromURL(url, targetPath);
      console.log(`[TEMPLATE] Download complete for ${templateName}`);
      resolve(true);
    } catch (err) {
      reject(err);
    }
  });
}

// Generate Cloud-Init config for NAT (User Mode)
// Configures DHCP networking automatically
function generateNATCloudInitConfig(vm) {
  const username = vm.username || 'root';
  const password = vm.password || 'password';
  const hostname = vm.hostname || 'hkvm-instance';

  // Build users section - support root and custom users
  let usersSection = `users:`;
  let chpasswdList = ``;
  
  if (username.toLowerCase() === 'root') {
    // If root user, configure root directly
    usersSection += `
  - name: root
    lock_passwd: false
    shell: /bin/bash
    homedir: /root`;
    chpasswdList = `    - root:${password}`;
  } else {
    // If custom user, create the user with sudo privileges
    usersSection += `
  - name: ${username}
    lock_passwd: false
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    homedir: /home/${username}
    createhome: true
    
  - name: root
    lock_passwd: false
    shell: /bin/bash`;
    chpasswdList = `    - ${username}:${password}
    - root:password`;
  }

  const config = `#cloud-config

# ================================================
# SYSTEM CONFIG
# ================================================
hostname: ${hostname}
manage_etc_hosts: true
preserve_hostname: false

# ================================================
# USERS & AUTH
# ================================================
${usersSection}

disable_root: false
ssh_pwauth: true

chpasswd:
  expire: false
  list:
${chpasswdList}

# ================================================
# SSH CONFIG
# ================================================
write_files:
  - path: /etc/ssh/sshd_config.d/50-cloud-init.conf
    owner: root:root
    permissions: '0644'
    content: |
      PermitRootLogin yes
      PasswordAuthentication yes

# ================================================
# NETWORKING (DHCP - Automatic)
# ================================================
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
      dhcp6: false

# ================================================
# FINAL MESSAGE
# ================================================
final_message: |
  ✓ VM CONFIGURED - NAT (User Mode)
  Hostname: ${hostname}
  Network: DHCP (Automatic)
  SSH: Default ports with forwarding
`;

  return config;
}

// Generate Cloud-Init config for Static Public IPv4 ONLY
// Configures static IPv4 with netplan v2 - NO DHCP
function generateStaticPublicIPv4CloudInitConfig(vm) {
  const username = vm.username || 'root';
  const password = vm.password || 'password';
  const hostname = vm.hostname || 'hkvm-instance';
  const ipv4_address = vm.ipv4_address || '10.0.0.100';
  const gateway = vm.gateway || vm.ipv4_gateway || '10.0.0.1';
  const netmask = vm.netmask || vm.ipv4_netmask || 24;
  const dns = (vm.dns_primary || '8.8.8.8').trim();
  const dns_secondary = (vm.dns_secondary || '8.8.4.4').trim();

  // Convert netmask to CIDR
  let cidr = netmask;
  if (typeof netmask === 'string' && netmask.includes('.')) {
    const parts = netmask.split('.');
    cidr = parts.reduce((sum, octet) => {
      return sum + parseInt(octet).toString(2).replace(/0/g, '').length;
    }, 0);
  }

  // Build users section - support root and custom users
  let usersSection = `users:`;
  let chpasswdList = ``;
  
  if (username.toLowerCase() === 'root') {
    // If root user, configure root directly
    usersSection += `
  - name: root
    lock_passwd: false
    shell: /bin/bash
    homedir: /root`;
    chpasswdList = `    - root:${password}`;
  } else {
    // If custom user, create the user with sudo privileges
    usersSection += `
  - name: ${username}
    lock_passwd: false
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    homedir: /home/${username}
    createhome: true
    
  - name: root
    lock_passwd: false
    shell: /bin/bash`;
    chpasswdList = `    - ${username}:${password}
    - root:password`;
  }

  const config = `#cloud-config

# ================================================
# SYSTEM CONFIG
# ================================================
hostname: ${hostname}
manage_etc_hosts: true
preserve_hostname: false

# ================================================
# USERS & AUTH
# ================================================
${usersSection}

disable_root: false
ssh_pwauth: true

chpasswd:
  expire: false
  list:
${chpasswdList}

# ================================================
# SSH CONFIG
# ================================================
write_files:
  - path: /etc/ssh/sshd_config.d/50-cloud-init.conf
    owner: root:root
    permissions: '0644'
    content: |
      PermitRootLogin yes
      PasswordAuthentication yes

  - path: /etc/netplan/99-static.yaml
    owner: root:root
    permissions: '0600'
    content: |
      network:
        version: 2
        renderer: networkd
        ethernets:
          ens3:
            dhcp4: false
            dhcp6: false
            addresses:
              - ${ipv4_address}/${cidr}
            routes:
              - to: 0.0.0.0/0
                via: ${gateway}
            nameservers:
              addresses: [${dns}, ${dns_secondary}]

  - path: /usr/local/bin/apply-network.sh
    owner: root:root
    permissions: '0755'
    content: |
      #!/bin/bash
      
      {
      echo "========== VERIFYING NETWORK CONFIG =========="
      echo "Time: $(date)"
      
      # Check if netplan config exists and is correct
      echo ""
      echo "Step 1: Checking netplan config..."
      if [ ! -f /etc/netplan/99-static.yaml ]; then
        echo "✗ Netplan config not found!"
        exit 1
      fi
      
      cat /etc/netplan/99-static.yaml
      
      # Apply (skip validate - netplan v2.12+ removed validate command)
      echo ""
      echo "Step 2: Applying netplan..."
      netplan apply || {
        echo "✗ Netplan apply failed!"
        systemctl status systemd-networkd || true
        exit 1
      }
      echo "✓ Netplan applied"
      
      sleep 2
      
      # Show final state
      echo ""
      echo "Step 3: Interface state AFTER netplan apply:"
      ip addr show
      ip route show
      
      echo ""
      echo "========== NETWORK CONFIG VERIFIED =========="
      } 2>&1 | tee /var/log/apply-network.log

# ================================================
# DISABLE WAIT-ONLINE + APPLY CONFIG
# ================================================
runcmd:
  - systemctl mask systemd-networkd-wait-online.service
  - systemctl mask systemd-network-online.target
  - bash /usr/local/bin/apply-network.sh

# ================================================
# FINAL MESSAGE
# ================================================
final_message: |
  ✓ VM CONFIGURED - Static IPv4
  IP: ${ipv4_address}/${cidr}
  Gateway: ${gateway}
  Hostname: ${hostname}
`;

  return config;
}

// Generate random MAC address
function generateMACAddress() {
  return 'fa:16:3e:' + [0, 1, 2].map(() => {
    return Math.floor(Math.random() * 256).toString(16).padStart(2, '0');
  }).join(':');
}

/**
 * Validate static IPv4 configuration
 * Returns {valid: boolean, error: string|null}
 */
function validateStaticIPv4Config(vm) {
  // Check required fields
  if (!vm.network_type || vm.network_type !== 'static_public') {
    return { valid: false, error: 'Network type must be static_public' };
  }
  
  if (!vm.ipv4_address) {
    return { valid: false, error: 'IPv4 address is required' };
  }
  
  // Validate IPv4 address format (basic check)
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(vm.ipv4_address)) {
    return { valid: false, error: `Invalid IPv4 address format: ${vm.ipv4_address}` };
  }
  
  // Validate each octet is 0-255
  const octets = vm.ipv4_address.split('.');
  for (const octet of octets) {
    const num = parseInt(octet);
    if (isNaN(num) || num < 0 || num > 255) {
      return { valid: false, error: `IPv4 octet out of range: ${octet}` };
    }
  }
  
  // Validate gateway
  const gateway = vm.gateway || vm.ipv4_gateway;
  if (gateway) {
    if (!ipv4Regex.test(gateway)) {
      return { valid: false, error: `Invalid gateway IPv4 format: ${gateway}` };
    }
    const gwOctets = gateway.split('.');
    for (const octet of gwOctets) {
      const num = parseInt(octet);
      if (isNaN(num) || num < 0 || num > 255) {
        return { valid: false, error: `Gateway octet out of range: ${octet}` };
      }
    }
  } else {
    return { valid: false, error: 'Gateway is required for static IPv4' };
  }
  
  // Validate netmask/CIDR
  let cidr = vm.netmask || vm.ipv4_netmask || 24;
  let cidrNum = parseInt(cidr);
  
  // If it contains dots, it's a dotted-decimal mask
  if (cidr.toString().includes('.')) {
    const parts = cidr.split('.');
    if (parts.length !== 4) {
      return { valid: false, error: 'Invalid netmask format' };
    }
    // Convert to CIDR to validate
    cidrNum = parts.reduce((sum, octet) => {
      const num = parseInt(octet);
      if (isNaN(num) || num < 0 || num > 255) {
        return -1;
      }
      return sum + num.toString(2).replace(/0/g, '').length;
    }, 0);
  }
  
  if (isNaN(cidrNum) || cidrNum < 1 || cidrNum > 32) {
    return { valid: false, error: `Invalid CIDR range: ${cidr} (must be 1-32)` };
  }
  
  // Validate DNS servers
  const dnsServers = (vm.dns_servers || vm.dns_primary || '8.8.8.8').split(',');
  for (const dns of dnsServers) {
    const cleanDns = dns.trim();
    if (cleanDns && !ipv4Regex.test(cleanDns)) {
      return { valid: false, error: `Invalid DNS server IP format: ${cleanDns}` };
    }
  }
  
  // Validate bridge device (if provided)
  if (vm.bridge_device && typeof vm.bridge_device === 'string') {
    if (!/^[a-z0-9]+$/.test(vm.bridge_device)) {
      return { valid: false, error: `Invalid bridge device name: ${vm.bridge_device}` };
    }
  }
  
  return { valid: true, error: null };
}

/**
 * Create Cloud-Init seed ISO with proper netplan v2 configuration
 * Includes meta-data, user-data, and network-config in correct format
 * Validates YAML syntax before creating ISO
 */
async function createCloudInitSeed(vm_id, vm) {
  return new Promise((resolve, reject) => {
    try {
      // Validate static IPv4 configuration if applicable
      if (vm.network_type === 'static_public') {
        const validation = validateStaticIPv4Config(vm);
        if (!validation.valid) {
          console.error(`[CLOUDINIT-${vm_id}] ✗ Validation Error: ${validation.error}`);
          return reject(new Error(`Static IPv4 validation failed: ${validation.error}`));
        }
        console.log(`[CLOUDINIT-${vm_id}] ✓ Static IPv4 configuration validated`);
      }
      
      const seedDir = path.join(VM_DIR, `vm-${vm_id}-seed-dir`);
      const seedIso = path.join(VM_DIR, `vm-${vm_id}-seed.iso`);
      const metaDataFile = path.join(seedDir, 'meta-data');
      const userDataFile = path.join(seedDir, 'user-data');
      const networkConfigFile = path.join(seedDir, 'network-config');

      // Clean up and create seed directory
      if (fs.existsSync(seedDir)) {
        fs.rmSync(seedDir, { recursive: true, force: true });
      }
      fs.mkdirSync(seedDir, { recursive: true });

      // Meta-data (instance information)
      const metaData = `instance-id: vm-${vm_id}
local-hostname: ${vm.hostname}
`;

      // Network-config is NO LONGER NEEDED - it's now embedded in user-data via runcmd
      // This avoids the interface naming race condition (eth0 vs ens3)
      const networkConfig = '';

      // User-data (cloud-init configuration) - Choose based on network type
      let userData;
      if (vm.network_type === 'nat') {
        console.log(`[CLOUDINIT-${vm_id}] Using NAT (User Mode) configuration`);
        userData = generateNATCloudInitConfig(vm);
      } else {
        console.log(`[CLOUDINIT-${vm_id}] Using Static Public IPv4 configuration`);
        userData = generateStaticPublicIPv4CloudInitConfig(vm);
      }

      // Validate cloud-init YAML before writing
      console.log(`[CLOUDINIT-${vm_id}] Validating cloud-init configuration...`);
      
      // Basic YAML validation - check for common issues
      const validateCloudInitConfig = (config) => {
        const errors = [];
        
        // Check if it starts with #cloud-config
        if (!config.startsWith('#cloud-config')) {
          errors.push('Must start with #cloud-config');
        }
        
        // Check for proper indentation (2 spaces)
        const lines = config.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          // Check tab characters (bad in YAML)
          if (line.includes('\t')) {
            errors.push(`Line ${i + 1}: Contains tab character (use spaces instead)`);
          }
          // Check indentation is multiple of 2
          const indent = line.match(/^ */)[0].length;
          if (indent > 0 && indent % 2 !== 0) {
            errors.push(`Line ${i + 1}: Invalid indentation (must be multiple of 2)`);
          }
        }
        
        return errors;
      };
      
      const validationErrors = validateCloudInitConfig(userData);
      if (validationErrors.length > 0) {
        console.warn(`[CLOUDINIT-${vm_id}] ⚠ Configuration warnings:`);
        validationErrors.forEach(err => console.warn(`  - ${err}`));
      } else {
        console.log(`[CLOUDINIT-${vm_id}] ✓ Cloud-init configuration is valid`);
      }

      // Write configuration files - only meta-data and user-data (no network-config)
      fs.writeFileSync(metaDataFile, metaData, 'utf8');
      fs.writeFileSync(userDataFile, userData, 'utf8');
      // networkConfigFile is no longer written

      console.log(`[CLOUDINIT-${vm_id}] ✓ Configuration files written`);
      console.log(`[CLOUDINIT-${vm_id}] - meta-data: ${(metaData.length / 1024).toFixed(2)}KB`);
      console.log(`[CLOUDINIT-${vm_id}] - user-data: ${(userData.length / 1024).toFixed(2)}KB`);
      console.log(`[CLOUDINIT-${vm_id}] ✓ Using embedded netplan config (no separate network-config file)`);

      // Create ISO from seed files
      // Use platform-appropriate tool
      let isoCommand;
      try {
        if (isWindows) {
          // On Windows, try mkisofs first
          try {
            isoCommand = `mkisofs -output "${seedIso}" -volid cidata -joliet -rock "${seedDir}"`;
            execSync(isoCommand, { stdio: 'pipe', shell: 'cmd' });
          } catch (e) {
            console.error(`[CLOUDINIT-${vm_id}] mkisofs not found on Windows`);
            throw new Error('ISO creation tool not available - install mkisofs');
          }
        } else {
          // On Linux, prefer genisoimage or mkisofs
          try {
            isoCommand = `genisoimage -output "${seedIso}" -volid cidata -joliet -rock "${seedDir}"`;
            execSync(isoCommand, { stdio: 'pipe', shell: '/bin/bash' });
          } catch (e) {
            try {
              isoCommand = `mkisofs -output "${seedIso}" -volid cidata -joliet -rock "${seedDir}"`;
              execSync(isoCommand, { stdio: 'pipe', shell: '/bin/bash' });
            } catch (e2) {
              console.error(`[CLOUDINIT-${vm_id}] Neither genisoimage nor mkisofs available`);
              throw new Error('ISO creation tool not available - install genisoimage or mkisofs');
            }
          }
        }
        
        console.log(`[CLOUDINIT-${vm_id}] ✓ ISO seed created: ${seedIso}`);
        
        // Verify ISO was created
        if (fs.existsSync(seedIso)) {
          const size = fs.statSync(seedIso).size;
          console.log(`[CLOUDINIT-${vm_id}] ✓ ISO size: ${(size / 1024).toFixed(2)}KB`);
          
          // Clean up seed directory after successful ISO creation
          try {
            fs.rmSync(seedDir, { recursive: true, force: true });
            console.log(`[CLOUDINIT-${vm_id}] ✓ Seed directory cleaned up`);
          } catch (e) {
            console.warn(`[CLOUDINIT-${vm_id}] ⚠ Could not clean seed directory`);
          }
          
          resolve(true);
        } else {
          throw new Error('ISO file not created');
        }
      } catch (isoError) {
        console.error(`[CLOUDINIT-${vm_id}] ✗ ISO creation failed: ${isoError.message}`);
        console.error(`[CLOUDINIT-${vm_id}] Please install: genisoimage, mkisofs, or cloud-utils`);
        logError('CLOUDINIT', vm_id, 'ISO creation', isoError);
        reject(new Error('ISO creation tool not available - install genisoimage, mkisofs, or cloud-utils'));
      }
    } catch (error) {
      console.error(`[CLOUDINIT-${vm_id}] Error: ${error.message}`);
      console.error(`[CLOUDINIT-${vm_id}] Stack: ${error.stack}`);
      reject(error);
    }
  });
}

async function startQemuVM(vm) {
  return new Promise((resolve, reject) => {
    try {
      // Use custom disk path from VM record, fallback to VM_DIR
      const vmDiskPath = vm.vm_disk_path || VM_DIR;
      const pidFile = path.join(vmDiskPath, `vm-${vm.vm_id}.pid`);
      const logFile = path.join(vmDiskPath, `vm-${vm.vm_id}.log`);
      
      // Validate CPU model - fallback to 'host' if model not available
      let cpuToUse = 'host';
      if (vm.custom_cpu_name) {
        // Custom CPU name + CPU model - use both for full flexibility
        // Format: -cpu <cpu_model>,model-id=Custom Name
        // Note: No quotes needed when using spawn() array format
        let baseCpuModel = 'host';
        if (vm.cpu_model && CPU_MODELS[vm.cpu_model]) {
          baseCpuModel = vm.cpu_model;
        }
        cpuToUse = `${baseCpuModel},model-id=${vm.custom_cpu_name}`;
        console.log(`[VM-${vm.vm_id}] Using custom CPU: ${vm.custom_cpu_name} (base: ${baseCpuModel})`);
      } else if (vm.cpu_model && CPU_MODELS[vm.cpu_model]) {
        cpuToUse = vm.cpu_model;
        console.log(`[VM-${vm.vm_id}] Using preset CPU: ${cpuToUse}`);
      } else if (vm.cpu_model) {
        console.warn(`[VM-${vm.vm_id}] CPU model '${vm.cpu_model}' not found, falling back to 'host'`);
        cpuToUse = 'host';
        // Also update the database to fix the VM's CPU model
        db.run(`UPDATE vms SET cpu_model = 'host' WHERE vm_id = ?`, [vm.vm_id], (err) => {
          if (!err) console.log(`[VM-${vm.vm_id}] Updated database: cpu_model -> 'host'`);
        });
      }
      
      // Build QEMU command line as array (safer than string concatenation)
      const args = [
        `-m`, `${vm.memory}`,
        `-smp`, `cores=${vm.cpu_cores},threads=${vm.cpu_threads},sockets=${vm.cpu_sockets}`,
        `-cpu`, cpuToUse,
        `-name`, `vm-${vm.vm_id}`,
        `-machine`, `${vm.machine_type || 'pc'},accel=kvm:tcg`,
        `-enable-kvm`,
        `-nographic`
      ];
      
      // SMBIOS Configuration
      const smbiosManufacturer = vm.smbios_manufacturer || vm.custom_smbios_manufacturer || 'QEMU';
      const smbiosaProduct = vm.smbios_product || 'KVM Virtual Machine';
      const smbiosaVersion = vm.smbios_version || '1.0';
      const smbiosaSerial = vm.smbios_serial || `vm-${vm.vm_id}`;
      const boardName = vm.board_name || 'Main-Board';
      
      args.push(`-smbios`, `type=0,vendor=${smbiosManufacturer},version=${smbiosaVersion}`);
      args.push(`-smbios`, `type=1,manufacturer=${smbiosManufacturer},product=${smbiosaProduct},version=${smbiosaVersion},serial=${smbiosaSerial}`);
      args.push(`-smbios`, `type=2,manufacturer=${smbiosManufacturer},product=${boardName},version=${smbiosaVersion}`);
      
      console.log(`[VM-${vm.vm_id}] SMBIOS Config:`);
      console.log(`[VM-${vm.vm_id}]   Manufacturer: ${smbiosManufacturer}`);
      console.log(`[VM-${vm.vm_id}]   Product: ${smbiosaProduct}`);
      console.log(`[VM-${vm.vm_id}]   Board: ${boardName}`);
      console.log(`[VM-${vm.vm_id}]   Serial: ${smbiosaSerial}`);
      
      // ACPI configuration
      if (vm.enable_acpi === 0) {
        args.push(`-no-acpi`);
      }
      
      // Boot settings - check if ISO should boot first or disk
      if (vm.boot_from_iso && vm.iso_attached) {
        // Boot from ISO first, then fall back to disk
        args.push(`-boot`, `order=d,menu=off`);  // d = CDROM, then fallback
        console.log(`[VM-${vm.vm_id}] Boot Order: ISO (${vm.iso_attached}) → Disk`);
      } else {
        // Boot from HDD/disk only
        args.push(`-boot`, `c`);
        console.log(`[VM-${vm.vm_id}] Boot Order: Disk only`);
      }
      
      // Disable floppy device completely to avoid fd0 errors
      args.push(`-drive`, `if=floppy,index=-1`);
      
      // Drives - root disk
      // Always use disk_file for root filesystem (allows resizing)
      args.push(`-drive`, `file=${vm.disk_file},format=qcow2,if=virtio,media=disk`);
      
      // ISO media (if attached) - CD/DVD drive
      if (vm.iso_attached) {
        const isoPath = path.join(ISO_DIR, vm.iso_attached);
        if (fs.existsSync(isoPath)) {
          args.push(`-drive`, `file=${isoPath},format=raw,media=cdrom,if=ide,index=0`);
          console.log(`[VM-${vm.vm_id}] ISO Media Attached: ${vm.iso_attached}`);
        } else {
          console.warn(`[VM-${vm.vm_id}] ISO file not found: ${vm.iso_attached}`);
        }
      }
      
      // Cloud-init seed disk (CD-ROM) - MUST have for cloud-init to work
      const seedIso = path.join(vmDiskPath, `vm-${vm.vm_id}-seed.iso`);
      if (fs.existsSync(seedIso)) {
        args.push(`-drive`, `file=${seedIso},format=raw,media=cdrom,if=ide,index=1`);
      }
      
      // Network Configuration - Support both NAT and Static IPv4
      const netdevId = 'n0';
      const macAddress = vm.mac_address || generateMACAddress();
      
      if (vm.network_type === 'nat') {
        // NAT (User Mode) Network with SSH port forwarding only
        const sshPort = vm.ssh_port || vm.ssh_port_static || 2222;
        
        // Add virtio network device
        args.push(`-device`, `virtio-net-pci,netdev=${netdevId},mac=${macAddress}`);
        
        // Add user-mode network with SSH port forwarding only (no HTTP)
        args.push(`-netdev`, `user,id=${netdevId},hostfwd=tcp::${sshPort}-:22`);
        
        console.log(`[VM-${vm.vm_id}] Network: NAT (User Mode) with SSH Port Forwarding`);
        console.log(`[VM-${vm.vm_id}] QEMU Command:`);
        console.log(`[VM-${vm.vm_id}]   -device virtio-net-pci,netdev=${netdevId},mac=${macAddress}`);
        console.log(`[VM-${vm.vm_id}]   -netdev user,id=${netdevId},hostfwd=tcp::${sshPort}-:22`);
        console.log(`[VM-${vm.vm_id}] SSH Port Forwarding: localhost:${sshPort} → VM:22`);
        console.log(`[VM-${vm.vm_id}] MAC Address: ${macAddress}`);
      } else {
        // Static Public IPv4 - Bridge Mode
        const bridgeDevice = vm.bridge_device || 'vmbr0';
        const dnsServers = vm.dns_servers || '8.8.8.8,8.8.4.4';
        
        // Add network device
        args.push(`-device`, `virtio-net-pci,netdev=${netdevId},mac=${macAddress}`);
        
        // Add bridge network interface
        args.push(`-netdev`, `bridge,id=${netdevId},br=${bridgeDevice}`);
        
        console.log(`[VM-${vm.vm_id}] Network: Static Public IPv4 (Bridge Mode)`);
        console.log(`[VM-${vm.vm_id}] QEMU Command:`);
        console.log(`[VM-${vm.vm_id}]   -device virtio-net-pci,netdev=${netdevId},mac=${macAddress}`);
        console.log(`[VM-${vm.vm_id}]   -netdev bridge,id=${netdevId},br=${bridgeDevice}`);
        console.log(`[VM-${vm.vm_id}] Bridge Device: ${bridgeDevice}`);
        console.log(`[VM-${vm.vm_id}] Configured Static IP: ${vm.ipv4_address}/${vm.netmask}`);
        console.log(`[VM-${vm.vm_id}] Gateway: ${vm.gateway}`);
        console.log(`[VM-${vm.vm_id}] DNS: ${dnsServers}`);
        console.log(`[VM-${vm.vm_id}] MAC Address: ${macAddress}`);
      }
      
      // Serial console with monitor support - stdin/stdout for direct terminal access
      args.push(`-serial`, `mon:stdio`);
      
      // Extra arguments if provided
      if (vm.extra_args) {
        args.push(vm.extra_args);
      }

      console.log(`[VM-${vm.vm_id}] CPU Config: ${vm.cpu_sockets} sockets x ${vm.cpu_cores} cores x ${vm.cpu_threads} threads = ${vm.cpus} total`);
      const cpuDisplayName = vm.custom_cpu_name || vm.cpu_model || 'host';
      console.log(`[VM-${vm.vm_id}] CPU Model: ${cpuDisplayName}`);
      console.log(`[VM-${vm.vm_id}] SMBIOS: ${vm.smbios_manufacturer} ${vm.smbios_product} (${vm.smbios_serial})`);
      console.log(`[VM-${vm.vm_id}] Network Mode: ${vm.network_type === 'nat' ? 'NAT (User Mode)' : 'Static Public IPv4'}`);
      if (vm.network_type !== 'nat') {
        console.log(`[VM-${vm.vm_id}] IPv4 Address: ${vm.ipv4_address}`);
      }
      console.log(`[VM-${vm.vm_id}] Template: ${vm.template_type} (${vm.os_type})`);
      console.log(`[VM-${vm.vm_id}] Starting: ${vm.vm_name}`);
      console.log(`[VM-${vm.vm_id}] Image File: ${vm.img_file}`);
      console.log(`[VM-${vm.vm_id}] Console: Direct terminal access via -nographic -serial mon:stdio`);

      // Use spawn for background process execution
      const qemuProcess = spawn('qemu-system-x86_64', args, {
        stdio: ['ignore', 'pipe', 'pipe'],  // stdin: ignore, stdout: pipe, stderr: pipe
        detached: true,  // Let process run independently
        shell: false
      });

      const pid = qemuProcess.pid;
      
      // Save PID to file for later management
      fs.writeFileSync(pidFile, pid.toString());
      console.log(`[VM-${vm.vm_id}] ✓ Started with PID: ${pid}`);
      
      // Capture QEMU output to log file with rotation
      const rotateLogIfNeeded = () => {
        if (fs.existsSync(logFile)) {
          const stat = fs.statSync(logFile);
          if (stat.size > 10 * 1024 * 1024) {  // 10MB
            const backupFile = `${logFile}.${Date.now()}.bak`;
            fs.renameSync(logFile, backupFile);
            console.log(`[VM-${vm.vm_id}] Log rotated: ${backupFile}`);
          }
        }
      };
      
      if (qemuProcess.stdout) {
        qemuProcess.stdout.on('data', (data) => {
          rotateLogIfNeeded();
          fs.appendFileSync(logFile, data.toString());
        });
      }
      
      if (qemuProcess.stderr) {
        qemuProcess.stderr.on('data', (data) => {
          rotateLogIfNeeded();
          fs.appendFileSync(logFile, data.toString());
        });
      }
      
      // Handle process exit
      qemuProcess.on('exit', (code, signal) => {
        console.log(`[VM-${vm.vm_id}] Process exited with code ${code}, signal ${signal}`);
        try {
          fs.unlinkSync(pidFile);
        } catch (e) {}
      });
      
      qemuProcess.on('error', (err) => {
        console.error(`[VM-${vm.vm_id}] Process error: ${err.message}`);
        logError('QEMU', vm.vm_id, 'startup', err);
      });

      resolve({ pid, success: true });
    } catch (error) {
      logError('QEMU', vm.vm_id, 'initialization', error);
      reject(new Error(`Failed to start VM: ${error.message}`));
    }
  });
}

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Redirect / to dashboard or login
app.get('/', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.redirect('/login');
});

// ============= SETTINGS ROUTES =============

// Get all settings (no auth required for reading defaults)
app.get('/api/settings', (req, res) => {
  const os = require('os');
  
  db.all(`SELECT setting_key, setting_value FROM settings`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    
    const settings = {
      panel_version: 'V2.0',
      panel_title: 'HKVM Panel V2.0',
      panel_description: 'Professional VM Management Panel',
      site_icon_url: 'https://i.imgur.com/0DmkSi4.png',
      session_timeout: 24,
      max_sessions: 10,
      // System information
      nodeVersion: process.version,
      platform: `${os.platform()} (${os.arch()})`,
      uptime: formatUptime(os.uptime())
    };

    // Override with DB values
    if (rows && rows.length > 0) {
      rows.forEach(row => {
        settings[row.setting_key] = row.setting_value;
      });
    }

    res.json(settings);
  });
});

// Helper function to format uptime
function formatUptime(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  
  if (days > 0) {
    return `${days}d ${hours}h ${minutes}m`;
  } else if (hours > 0) {
    return `${hours}h ${minutes}m`;
  } else {
    return `${minutes}m`;
  }
}

// Update setting (admin only)
app.post('/api/settings/:key', checkAuth, checkAdmin, (req, res) => {
  const { key } = req.params;
  const { value } = req.body;

  if (value === null || value === undefined) {
    return res.status(400).json({ error: 'Value required' });
  }

  db.run(
    `INSERT OR REPLACE INTO settings (setting_key, setting_value, updated_at) VALUES (?, ?, datetime('now'))`,
    [key, String(value)],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, key, value });
    }
  );
});

// Update multiple settings (admin only)
app.put('/api/settings', checkAuth, checkAdmin, (req, res) => {
  const settings = req.body;
  let completed = 0;
  const total = Object.keys(settings).length;
  const errors = [];

  if (total === 0) {
    return res.status(400).json({ error: 'No settings provided' });
  }

  Object.entries(settings).forEach(([key, value]) => {
    db.run(
      `INSERT OR REPLACE INTO settings (setting_key, setting_value, updated_at) VALUES (?, ?, datetime('now'))`,
      [key, String(value)],
      (err) => {
        completed++;
        if (err) {
          errors.push({ key, error: err.message });
        }
        
        if (completed === total) {
          if (errors.length > 0) {
            res.status(500).json({ success: false, errors, saved: total - errors.length });
          } else {
            res.json({ success: true, saved: total });
          }
        }
      }
    );
  });
});

// Change admin password (admin only)
app.post('/api/admin/change-password', checkAuth, checkAdmin, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password required' });
  }
  
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }
  
  const userId = req.session.userId;
  
  // Get current user's password
  db.get(
    `SELECT password FROM users WHERE id = ?`,
    [userId],
    (err, user) => {
      if (err || !user) {
        return res.status(500).json({ error: 'User not found' });
      }
      
      // Verify current password
      if (!bcrypt.compareSync(currentPassword, user.password)) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }
      
      // Hash new password
      const hashedPassword = bcrypt.hashSync(newPassword, 10);
      
      // Update password in database
      db.run(
        `UPDATE users SET password = ?, updated_at = datetime('now') WHERE id = ?`,
        [hashedPassword, userId],
        (err) => {
          if (err) {
            console.error('Error updating password:', err);
            return res.status(500).json({ error: 'Failed to update password' });
          }
          res.json({ success: true, message: 'Password changed successfully' });
        }
      );
    }
  );
});

// ============= DISCORD SETTINGS API =============

// Get Discord settings (admin only)
app.get('/api/admin/discord-settings', checkAuth, checkAdmin, (req, res) => {
  db.get(`SELECT * FROM discord_settings LIMIT 1`, (err, settings) => {
    if (err) return res.status(500).json({ error: err.message });
    
    if (!settings) {
      // Return default empty settings
      return res.json({
        enabled: 0,
        client_id: '',
        client_secret: '',
        redirect_uri: '',
        bot_token: '',
        guild_id: '',
        auto_role_id: '',
        updated_at: null
      });
    }

    // Don't send client_secret to frontend for security
    const safe = { ...settings };
    safe.client_secret = safe.client_secret ? '••••••••' : '';
    safe.bot_token = safe.bot_token ? '••••••••' : '';
    res.json(safe);
  });
});

// Update Discord settings (admin only)
app.put('/api/admin/discord-settings', checkAuth, checkAdmin, (req, res) => {
  const { enabled, client_id, client_secret, redirect_uri, bot_token, guild_id, auto_role_id } = req.body;

  if (!client_id || !client_secret || !redirect_uri) {
    if (enabled) {
      return res.status(400).json({ error: 'Client ID, Client Secret, and Redirect URI are required' });
    }
  }

  // Get current settings to preserve secrets if not being changed
  db.get(`SELECT * FROM discord_settings LIMIT 1`, (err, current) => {
    if (err) return res.status(500).json({ error: err.message });

    const finalClientSecret = (client_secret && client_secret !== '••••••••') ? client_secret : (current?.client_secret || '');
    const finalBotToken = (bot_token && bot_token !== '••••••••') ? bot_token : (current?.bot_token || '');

    if (current) {
      // Update existing
      db.run(
        `UPDATE discord_settings SET 
         enabled = ?, client_id = ?, client_secret = ?, redirect_uri = ?, 
         bot_token = ?, guild_id = ?, auto_role_id = ?, updated_at = datetime('now')
         WHERE id = ?`,
        [enabled ? 1 : 0, client_id || '', finalClientSecret, redirect_uri || '', 
         finalBotToken, guild_id || '', auto_role_id || '', current.id],
        (err) => {
          if (err) return res.status(500).json({ error: err.message });
          
          const response = { success: true, message: 'Discord settings updated' };
          if (client_secret === '••••••••' || !client_secret) {
            response.message += ' (Client Secret preserved)';
          }
          res.json(response);
        }
      );
    } else {
      // Insert new
      db.run(
        `INSERT INTO discord_settings (enabled, client_id, client_secret, redirect_uri, bot_token, guild_id, auto_role_id) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [enabled ? 1 : 0, client_id || '', finalClientSecret, redirect_uri || '', 
         finalBotToken, guild_id || '', auto_role_id || ''],
        (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ success: true, message: 'Discord settings created' });
        }
      );
    }
  });
});

// ============= USER PROFILE API =============

// Get user profile
app.get('/api/user/profile', checkAuth, (req, res) => {
  const userId = req.session.userId;
  if (!userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  db.get(
    `SELECT id, username, email, full_name, role, created_at, last_login FROM users WHERE id = ?`,
    [userId],
    (err, user) => {
      if (err) {
        console.error('[API Error] Failed to load profile:', err);
        // Fallback: try without full_name and last_login columns in case they don't exist yet
        db.get(
          `SELECT id, username, email, role, created_at FROM users WHERE id = ?`,
          [userId],
          (err2, user2) => {
            if (err2 || !user2) {
              return res.status(404).json({ error: 'User not found' });
            }
            // Add null values for missing columns
            user2.full_name = null;
            user2.last_login = null;
            res.json(user2);
          }
        );
        return;
      }
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      res.json(user);
    }
  );
});

// Update user profile (name & email)
app.put('/api/user/profile', checkAuth, (req, res) => {
  const { full_name, email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  
  db.run(
    `UPDATE users SET full_name = ?, email = ? WHERE id = ?`,
    [full_name || '', email, req.session.userId],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: 'Email already in use' });
        }
        return res.status(500).json({ error: err.message });
      }
      res.json({ success: true, message: 'Profile updated successfully' });
    }
  );
});

// Change password
app.put('/api/user/password', checkAuth, (req, res) => {
  const { current_password, new_password } = req.body;
  
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'All password fields are required' });
  }
  
  if (new_password.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }
  
  // Get current password hash
  db.get(`SELECT password FROM users WHERE id = ?`, [req.session.userId], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Verify current password
    if (!bcrypt.compareSync(current_password, user.password)) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const hashedPassword = bcrypt.hashSync(new_password, 10);
    
    // Update password
    db.run(
      `UPDATE users SET password = ? WHERE id = ?`,
      [hashedPassword, req.session.userId],
      function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json({ success: true, message: 'Password changed successfully' });
      }
    );
  });
});

// ============= SSH CONNECTION API =============

// SSH Connect endpoint - Test SSH connection
app.post('/api/ssh/connect', checkAuth, (req, res) => {
  const { vmId, host, port, username } = req.body;
  const userId = req.session.userId;
  
  if (!vmId || !host || !port || !username) {
    return res.status(400).json({ error: 'Missing connection parameters' });
  }
  
  // Verify VM ownership
  db.get(`SELECT * FROM vms WHERE vm_id = ? AND owner_id = ?`, [vmId, userId], (err, vm) => {
    if (err || !vm) {
      return res.status(403).json({ error: 'VM not found or access denied' });
    }
    
    // Generate session ID
    const sessionId = require('crypto').randomBytes(16).toString('hex');
    
    // Store connection info in memory
    global.sshSessions = global.sshSessions || {};
    global.sshSessions[sessionId] = {
      vmId: vmId,
      userId: userId,
      host: host,
      port: parseInt(port),
      username: username,
      password: null,
      createdAt: Date.now(),
      client: null
    };
    
    // Try to create SSH connection to verify it works
    const conn = new Client();
    const connConfig = {
      host: host,
      port: parseInt(port),
      username: username,
      password: '',
      tryKeyboard: true,
      readyTimeout: 5000,
      strict: false
    };
    
    conn.on('ready', () => {
      console.log(`[SSH] Connected to ${host}:${port}`);
      global.sshSessions[sessionId].client = conn;
      res.json({
        success: true,
        sessionId: sessionId,
        message: 'SSH session created and connected'
      });
    });
    
    conn.on('error', (err) => {
      console.log(`[SSH] Connection error: ${err.message}`);
      delete global.sshSessions[sessionId];
      res.status(500).json({ 
        error: 'SSH connection failed: ' + err.message 
      });
    });
    
    conn.connect(connConfig);
  });
});

// SSH Command endpoint - Execute command on VM
app.post('/api/ssh/command', checkAuth, (req, res) => {
  const { vmId, command } = req.body;
  const userId = req.session.userId;
  
  if (!vmId || !command) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  // Find an active session for this VM
  let session = null;
  if (global.sshSessions) {
    for (const [id, s] of Object.entries(global.sshSessions)) {
      if (s.vmId === parseInt(vmId) && s.userId === userId && s.client) {
        session = s;
        break;
      }
    }
  }
  
  if (!session || !session.client) {
    return res.status(404).json({ error: 'SSH session not found. Connect first.' });
  }
  
  // Execute command via SSH
  session.client.exec(command, (err, stream) => {
    if (err) {
      return res.status(500).json({ 
        error: 'Command execution failed: ' + err.message 
      });
    }
    
    let output = '';
    let errorOutput = '';
    
    stream.on('close', () => {
      res.json({
        success: true,
        output: output || errorOutput || '(no output)',
        error: errorOutput || null
      });
    });
    
    stream.on('data', (data) => {
      output += data.toString();
    });
    
    stream.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });
  });
});

// ============= 404 HANDLER =============
app.use((req, res) => {
  res.status(404).render('users/404', {
    title: 'Page Not Found - HKVM Panel',
    message: 'Page not found'
  });
});

// START SERVER
initializeDatabase();

// WebSocket handler for VM console
const vmConsoles = new Map();
const sshSessions = new Map();

wss.on('connection', (ws, req) => {
  const url = req.url;
  console.log(`[WebSocket] New connection: ${url}`);
  
  // SSH Terminal WebSocket - Path: /ssh-terminal
  if (url.startsWith('/ssh-terminal')) {
    console.log(`[SSH-Terminal] New SSH terminal connection`);
    
    ws.on('message', async (message) => {
      try {
        const msg = JSON.parse(message.toString());
        
        if (msg.type === 'connect') {
          const { vmId, host, port, username, password } = msg;
          
          console.log(`[SSH-${vmId}] Initiating SSH connection to ${username}@${host}:${port}`);
          
          // Verify VM ownership
          db.get(`SELECT owner_id FROM vms WHERE vm_id = ?`, [vmId], (err, vm) => {
            if (err || !vm) {
              ws.send(JSON.stringify({ type: 'error', message: 'VM not found' }));
              return;
            }
            
            // Create SSH client
            const sshClient = new Client();
            
            sshClient.on('ready', () => {
              console.log(`[SSH-${vmId}] SSH client ready, opening shell`);
              
              sshClient.shell({ term: 'xterm-256color' }, (err, stream) => {
                if (err) {
                  console.error(`[SSH-${vmId}] Shell error:`, err.message);
                  ws.send(JSON.stringify({ type: 'error', message: 'Failed to open shell' }));
                  sshClient.end();
                  return;
                }
                
                console.log(`[SSH-${vmId}] Shell opened successfully`);
                ws.send(JSON.stringify({ type: 'connected' }));
                
                // Store session
                const sessionId = `${vmId}-${Date.now()}`;
                sshSessions.set(sessionId, { stream, client: sshClient, vmId });
                
                // Send raw data from SSH to WebSocket (binary, not JSON)
                // This preserves ANSI escape codes for proper terminal rendering
                stream.on('data', (data) => {
                  if (ws.readyState === WebSocket.OPEN) {
                    // Send raw binary data directly to xterm.js
                    ws.send(data, { binary: true });
                  }
                });
                
                stream.on('close', () => {
                  console.log(`[SSH-${vmId}] Shell closed`);
                  sshClient.end();
                  sshSessions.delete(sessionId);
                  if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'closed' }));
                  }
                });
                
                stream.on('error', (err) => {
                  console.error(`[SSH-${vmId}] Stream error:`, err.message);
                  sshSessions.delete(sessionId);
                  if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'error', message: err.message }));
                  }
                });
                
                // Store current session for this WebSocket
                ws.sshSessionId = sessionId;
              });
            });
            
            sshClient.on('error', (err) => {
              console.error(`[SSH-${vmId}] Connection error:`, err.message);
              ws.send(JSON.stringify({ type: 'error', message: `SSH Connection failed: ${err.message}` }));
              if (ws.readyState === WebSocket.OPEN) {
                ws.close();
              }
            });
            
            sshClient.on('close', () => {
              console.log(`[SSH-${vmId}] SSH connection closed`);
              if (ws.readyState === WebSocket.OPEN) {
                ws.close();
              }
            });
            
            // Connect to SSH server
            sshClient.connect({
              host: host,
              port: parseInt(port),
              username: username,
              password: password,
              readyTimeout: 30000,
              algorithms: {
                serverHostKey: ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519']
              }
            });
          });
        } else if (msg.type === 'input' && ws.sshSessionId) {
          // Send user input to SSH shell (handle binary input)
          const session = sshSessions.get(ws.sshSessionId);
          if (session && session.stream) {
            session.stream.write(msg.data);
          }
        }
      } catch (err) {
        console.error('[SSH-Terminal] Message error:', err.message);
        ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
      }
    });
    
    ws.on('close', () => {
      console.log(`[SSH-Terminal] WebSocket closed`);
      if (ws.sshSessionId) {
        const session = sshSessions.get(ws.sshSessionId);
        if (session) {
          try {
            session.stream.end();
            session.client.end();
          } catch (e) {
            console.error('[SSH-Terminal] Error closing session:', e.message);
          }
          sshSessions.delete(ws.sshSessionId);
        }
      }
    });
    
    ws.on('error', (err) => {
      console.error(`[SSH-Terminal] WebSocket error:`, err.message);
    });
    
    return;
  }
  
  // Extract vmId from URL path like /console/1 or just /1
  let vmId = null;
  if (url.includes('/console/')) {
    vmId = url.split('/console/')[1].split('?')[0];
  } else {
    vmId = url.split('/').pop().split('?')[0];
  }
  
  if (!vmId || vmId === '' || isNaN(vmId)) {
    console.log(`[WebSocket] Invalid vmId: "${vmId}"`);
    ws.send(JSON.stringify({ type: 'output', data: '\x1b[31m✗ Invalid VM ID\x1b[0m\r\n' }));
    ws.close();
    return;
  }

  console.log(`[Console-${vmId}] Client connected`);
  
  const logFile = path.join(VM_DIR, `vm-${vmId}.log`);
  let lastSize = 0;
  let watchInterval = null;

  // Send initial content
  db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vmId], (err, vm) => {
    if (err) {
      console.error(`[Console-${vmId}] DB error:`, err.message);
      ws.send(JSON.stringify({ type: 'output', data: `\x1b[31m✗ Database error\x1b[0m\r\n` }));
      return;
    }

    if (!vm) {
      console.log(`[Console-${vmId}] VM not found`);
      ws.send(JSON.stringify({ type: 'output', data: `\x1b[31m✗ VM ${vmId} not found\x1b[0m\r\n` }));
      return;
    }

    let intro = '';
    if (vm.status === 'running') {
      intro = `\x1b[32m✓ VM ${vmId} is RUNNING\x1b[0m\r\n`;
    } else {
      intro = `\x1b[33m⚠ VM ${vmId} is ${vm.status.toUpperCase()}\x1b[0m\r\n`;
    }

    // Read and send existing log
    if (fs.existsSync(logFile)) {
      try {
        const content = fs.readFileSync(logFile, 'utf8');
        lastSize = content.length;
        ws.send(JSON.stringify({ 
          type: 'output', 
          data: intro + content 
        }));
        console.log(`[Console-${vmId}] Sent ${content.length} bytes of log`);
      } catch (e) {
        console.error(`[Console-${vmId}] Read error:`, e.message);
        ws.send(JSON.stringify({ type: 'output', data: intro + '\x1b[33m(Log file error)\x1b[0m\r\n' }));
      }
    } else {
      ws.send(JSON.stringify({ type: 'output', data: intro + '\x1b[36m[Console ready]\x1b[0m\r\n' }));
    }

    // Start watching for new output (50ms interval for near real-time)
    watchInterval = setInterval(() => {
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        if (watchInterval) clearInterval(watchInterval);
        return;
      }

      try {
        if (fs.existsSync(logFile)) {
          const stat = fs.statSync(logFile);
          if (stat.size > lastSize) {
            const fd = fs.openSync(logFile, 'r');
            const buffer = Buffer.alloc(stat.size - lastSize);
            fs.readSync(fd, buffer, 0, stat.size - lastSize, lastSize);
            fs.closeSync(fd);
            
            lastSize = stat.size;
            const newData = buffer.toString('utf8');
            
            // Send to all clients for this VM
            if (vmConsoles.has(vmId)) {
              vmConsoles.get(vmId).forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                  client.send(JSON.stringify({ type: 'output', data: newData }));
                }
              });
            }
          }
        }
      } catch (e) {
        console.error(`[Console-${vmId}] Watch error:`, e.message);
      }
    }, 50);
  });

  // Store client
  if (!vmConsoles.has(vmId)) {
    vmConsoles.set(vmId, []);
  }
  vmConsoles.get(vmId).push(ws);

  // Handle input from terminal
  ws.on('message', (message) => {
    try {
      const msg = JSON.parse(message);
      if (msg.type === 'input' && msg.data) {
        // Append to log file
        fs.appendFileSync(logFile, msg.data);
        
        // Broadcast to other clients
        if (vmConsoles.has(vmId)) {
          vmConsoles.get(vmId).forEach(client => {
            if (client !== ws && client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({ type: 'output', data: msg.data }));
            }
          });
        }
        
        console.log(`[Console-${vmId}] Input: ${msg.data.length} bytes`);
      }
    } catch (e) {
      console.error(`[Console-${vmId}] Message parse error:`, e.message);
    }
  });

  // Handle disconnect
  ws.on('close', () => {
    console.log(`[Console-${vmId}] Client disconnected`);
    
    if (vmConsoles.has(vmId)) {
      const clients = vmConsoles.get(vmId);
      const idx = clients.indexOf(ws);
      if (idx > -1) {
        clients.splice(idx, 1);
      }
      
      // Clean up interval if no more clients
      if (clients.length === 0) {
        vmConsoles.delete(vmId);
      }
    }
  });

  ws.on('error', (error) => {
    console.error(`[Console-${vmId}] WebSocket error:`, error.message);
  });
});

// ============= INITIALIZE API ROUTES =============
// All API routes are defined inline in app.js
// No separate routes module needed

server.listen(PORT, async () => {
  // Fix any VMs with invalid CPU models on startup
  const validCpuModels = Object.keys(CPU_MODELS);
  db.all(`SELECT vm_id, cpu_model FROM vms WHERE cpu_model NOT IN (${validCpuModels.map(() => '?').join(',')})`, validCpuModels, (err, vms) => {
    if (!err && vms && vms.length > 0) {
      console.log(`[Startup] Found ${vms.length} VMs with invalid CPU models, fixing...`);
      vms.forEach(vm => {
        console.warn(`[Startup] VM ${vm.vm_id}: CPU model '${vm.cpu_model}' is not available, resetting to 'host'`);
        db.run(`UPDATE vms SET cpu_model = 'host' WHERE vm_id = ?`, [vm.vm_id]);
      });
    }
  });

  console.log(`
╔════════════════════════════════════════════════════════════╗
║           HOPINGBOYZ VM MANAGEMENT PANEL V3.0              ║
║          Advanced VM Management & Control Panel            ║
╚════════════════════════════════════════════════════════════╝

✓ Server: http://localhost:${PORT}
✓ Database: ${dbPath}
✓ VM Directory: ${VM_DIR}

Open http://localhost:${PORT} to begin
  `);
});

module.exports = app;
