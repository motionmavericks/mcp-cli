const fs = require('fs');
const path = require('path');
const os = require('os');

class Config {
  constructor() {
    this.configDir = path.join(os.homedir(), '.mcp-cli');
    this.configFile = path.join(this.configDir, 'config.json');
    this.ensureConfigDir();
  }
  
  ensureConfigDir() {
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true });
    }
  }
  
  load() {
    try {
      if (fs.existsSync(this.configFile)) {
        const data = fs.readFileSync(this.configFile, 'utf8');
        return JSON.parse(data);
      }
    } catch (error) {
      console.warn('Failed to load config:', error.message);
    }
    return {
      serverUrl: 'https://mcp.mvrx.com.au'
    };
  }
  
  save(config) {
    try {
      fs.writeFileSync(this.configFile, JSON.stringify(config, null, 2));
    } catch (error) {
      throw new Error('Failed to save config: ' + error.message);
    }
  }
  
  get(key) {
    const config = this.load();
    return key ? config[key] : config;
  }
  
  set(key, value) {
    const config = this.load();
    config[key] = value;
    this.save(config);
  }
  
  remove(key) {
    const config = this.load();
    delete config[key];
    this.save(config);
  }
  
  getConfigPath() {
    return this.configFile;
  }
}

module.exports = new Config();