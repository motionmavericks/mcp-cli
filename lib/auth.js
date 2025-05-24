const inquirer = require('inquirer');
const axios = require('axios');
const config = require('./config');
const chalk = require('chalk');

class Auth {
  constructor() {
    this.baseURL = 'https://mcp.mvrx.com.au/api';
  }
  
  async login() {
    const answers = await inquirer.prompt([
      {
        type: 'password',
        name: 'password',
        message: 'Enter MCP server password:',
        mask: '*'
      }
    ]);
    
    try {
      const response = await axios.post(`${this.baseURL}/auth/login`, {
        password: answers.password
      });
      
      const { token, user } = response.data;
      
      // Store credentials
      config.set('token', token);
      config.set('user', user || 'admin');
      
      return { token, user };
    } catch (error) {
      if (error.response?.status === 401) {
        throw new Error('Invalid password');
      }
      throw new Error('Login failed: ' + (error.response?.data?.message || error.message));
    }
  }
  
  async logout() {
    config.remove('token');
    config.remove('user');
  }
  
  async getToken() {
    return config.get('token');
  }
  
  async isLoggedIn() {
    const token = await this.getToken();
    return !!token;
  }
  
  async getUser() {
    return config.get('user');
  }
}

module.exports = new Auth();