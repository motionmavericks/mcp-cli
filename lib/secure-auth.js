const inquirer = require('inquirer');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const chalk = require('chalk');

class SecureAuth {
  constructor() {
    this.baseURL = process.env.MCP_API_URL || 'https://mcp.mvrx.com.au/api';
    this.configDir = path.join(os.homedir(), '.mcp-cli');
    this.configFile = path.join(this.configDir, 'config.enc');
    this.keyFile = path.join(this.configDir, '.key');
    
    // Ensure config directory exists
    this.ensureConfigDir();
  }
  
  async ensureConfigDir() {
    try {
      await fs.mkdir(this.configDir, { recursive: true, mode: 0o700 });
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
  }
  
  // Generate or retrieve encryption key
  async getEncryptionKey() {
    try {
      const keyData = await fs.readFile(this.keyFile);
      return keyData;
    } catch (error) {
      if (error.code === 'ENOENT') {
        const key = crypto.randomBytes(32);
        await fs.writeFile(this.keyFile, key, { mode: 0o600 });
        return key;
      }
      throw error;
    }
  }
  
  // Encrypt data
  async encrypt(data) {
    const key = await this.getEncryptionKey();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher('aes-256-cbc', key);
    
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return { 
      iv: iv.toString('hex'), 
      encrypted 
    };
  }
  
  // Decrypt data
  async decrypt(encryptedData) {
    const key = await this.getEncryptionKey();
    const decipher = crypto.createDecipher('aes-256-cbc', key);
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return JSON.parse(decrypted);
  }
  
  // Secure config storage
  async setConfig(key, value) {
    let config = {};
    
    try {
      const encrypted = await fs.readFile(this.configFile);
      config = await this.decrypt(JSON.parse(encrypted.toString()));
    } catch (error) {
      // File doesn't exist or is corrupted, start fresh
    }
    
    config[key] = value;
    config.lastAccess = new Date().toISOString();
    
    const encrypted = await this.encrypt(config);
    await fs.writeFile(this.configFile, JSON.stringify(encrypted), { mode: 0o600 });
  }
  
  async getConfig(key) {
    try {
      const encrypted = await fs.readFile(this.configFile);
      const config = await this.decrypt(JSON.parse(encrypted.toString()));
      return config[key];
    } catch (error) {
      return null;
    }
  }
  
  async removeConfig(key) {
    try {
      const encrypted = await fs.readFile(this.configFile);
      const config = await this.decrypt(JSON.parse(encrypted.toString()));
      delete config[key];
      
      const newEncrypted = await this.encrypt(config);
      await fs.writeFile(this.configFile, JSON.stringify(newEncrypted), { mode: 0o600 });
    } catch (error) {
      // Config file doesn't exist, nothing to remove
    }
  }
  
  // Validate server certificate
  async validateServer() {
    try {
      const response = await axios.get(`${this.baseURL.replace('/api', '')}`, {
        timeout: 10000,
        httpsAgent: {
          rejectUnauthorized: true // Enforce SSL certificate validation
        }
      });
      return response.status === 200;
    } catch (error) {
      console.error(chalk.red('Server validation failed:'), error.message);
      return false;
    }
  }
  
  async login() {
    // Validate server first
    const serverValid = await this.validateServer();
    if (!serverValid) {
      throw new Error('Cannot connect to server or SSL certificate invalid');
    }
    
    const answers = await inquirer.prompt([
      {
        type: 'password',
        name: 'password',
        message: 'Enter MCP server password:',
        mask: '*',
        validate: (input) => {
          if (!input || input.length < 8) {
            return 'Password must be at least 8 characters';
          }
          return true;
        }
      }
    ]);
    
    try {
      const response = await axios.post(`${this.baseURL}/auth/login`, 
        { password: answers.password },
        {
          timeout: 30000,
          httpsAgent: {
            rejectUnauthorized: true
          },
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'MCP-CLI/1.0.0'
          }
        }
      );
      
      const { token, user } = response.data;
      
      if (!token || typeof token !== 'string') {
        throw new Error('Invalid response from server');
      }
      
      // Store credentials securely
      await this.setConfig('token', token);
      await this.setConfig('user', user || 'admin');
      await this.setConfig('loginTime', new Date().toISOString());
      
      console.log(chalk.green('Login successful!'));
      return { token, user };
      
    } catch (error) {
      if (error.response?.status === 401) {
        throw new Error('Invalid password');
      } else if (error.code === 'ECONNREFUSED') {
        throw new Error('Cannot connect to server');
      } else if (error.code === 'CERT_HAS_EXPIRED') {
        throw new Error('Server SSL certificate has expired');
      } else if (error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
        throw new Error('Cannot verify server SSL certificate');
      }
      
      throw new Error('Login failed: ' + (error.response?.data?.message || error.message));
    }
  }
  
  async logout() {
    try {
      const token = await this.getToken();
      if (token) {
        // Notify server of logout
        await axios.post(`${this.baseURL}/auth/logout`, {}, {
          headers: { Authorization: `Bearer ${token}` },
          timeout: 10000
        });
      }
    } catch (error) {
      // Continue with local logout even if server request fails
      console.warn(chalk.yellow('Warning: Could not notify server of logout'));
    }
    
    // Clear local credentials
    await this.removeConfig('token');
    await this.removeConfig('user');
    await this.removeConfig('loginTime');
    
    console.log(chalk.green('Logged out successfully'));
  }
  
  async getToken() {
    const token = await this.getConfig('token');
    const loginTime = await this.getConfig('loginTime');
    
    if (!token || !loginTime) {
      return null;
    }
    
    // Check if token is expired (2 hours)
    const loginDate = new Date(loginTime);
    const now = new Date();
    const hoursDiff = (now - loginDate) / (1000 * 60 * 60);
    
    if (hoursDiff > 2) {
      await this.logout();
      return null;
    }
    
    return token;
  }
  
  async isLoggedIn() {
    const token = await this.getToken();
    return !!token;
  }
  
  async getUser() {
    return await this.getConfig('user');
  }
  
  // Clean up old config files and keys
  async cleanup() {
    try {
      await fs.unlink(this.configFile);
      await fs.unlink(this.keyFile);
      console.log(chalk.green('Configuration cleaned up'));
    } catch (error) {
      // Files might not exist
    }
  }
}

module.exports = new SecureAuth();