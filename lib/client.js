const axios = require('axios');
const chalk = require('chalk');
const ora = require('ora');
const auth = require('./auth');
const config = require('./config');

class MCPClient {
  constructor() {
    this.baseURL = 'https://mcp.mvrx.com.au/api';
    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 30000
    });
    
    // Add auth interceptor
    this.client.interceptors.request.use(async (config) => {
      const token = await auth.getToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });
    
    // Add response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          throw new Error('Authentication required. Please run "mcp login"');
        }
        throw error;
      }
    );
  }
  
  async listServers() {
    const spinner = ora('Fetching servers...').start();
    try {
      const response = await this.client.get('/servers');
      spinner.succeed('Servers loaded');
      return response.data;
    } catch (error) {
      spinner.fail('Failed to fetch servers');
      throw error;
    }
  }
  
  async installServer(serverId) {
    const spinner = ora(`Installing ${serverId}...`).start();
    try {
      await this.client.post(`/servers/${serverId}/install`);
      spinner.succeed(`${serverId} installed successfully`);
    } catch (error) {
      spinner.fail(`Failed to install ${serverId}`);
      throw error;
    }
  }
  
  async startServer(serverId) {
    const spinner = ora(`Starting ${serverId}...`).start();
    try {
      await this.client.post(`/servers/${serverId}/start`);
      spinner.succeed(`${serverId} started successfully`);
    } catch (error) {
      spinner.fail(`Failed to start ${serverId}`);
      throw error;
    }
  }
  
  async stopServer(serverId) {
    const spinner = ora(`Stopping ${serverId}...`).start();
    try {
      await this.client.post(`/servers/${serverId}/stop`);
      spinner.succeed(`${serverId} stopped successfully`);
    } catch (error) {
      spinner.fail(`Failed to stop ${serverId}`);
      throw error;
    }
  }
  
  async restartServer(serverId) {
    const spinner = ora(`Restarting ${serverId}...`).start();
    try {
      await this.client.post(`/servers/${serverId}/restart`);
      spinner.succeed(`${serverId} restarted successfully`);
    } catch (error) {
      spinner.fail(`Failed to restart ${serverId}`);
      throw error;
    }
  }
  
  async getStatus() {
    try {
      const response = await this.client.get('/status');
      return {
        endpoint: this.baseURL,
        connected: true,
        ...response.data
      };
    } catch (error) {
      return {
        endpoint: this.baseURL,
        connected: false,
        error: error.message
      };
    }
  }
  
  async listApiKeys() {
    const response = await this.client.get('/keys');
    return response.data;
  }
  
  async createApiKey(name) {
    const response = await this.client.post('/keys', { name });
    return response.data;
  }
  
  async revokeApiKey(keyId) {
    await this.client.delete(`/keys/${keyId}`);
  }
  
  async useTool(serverId, tool, args = []) {
    const spinner = ora(`Executing ${serverId}:${tool}...`).start();
    try {
      const response = await this.client.post(`/servers/${serverId}/tools/${tool}`, {
        args: args
      });
      spinner.succeed(`Tool executed successfully`);
      return response.data.result;
    } catch (error) {
      spinner.fail(`Tool execution failed`);
      throw error;
    }
  }
}

module.exports = MCPClient;