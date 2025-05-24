# MCP CLI

Command-line interface for managing MCP (Model Context Protocol) servers.

## Installation

```bash
npm install -g @motionmavericks/mcp-cli
```

## Quick Start

1. **Login to MCP server:**
   ```bash
   mcp login
   # Enter password: mcp2024
   ```

2. **List available servers:**
   ```bash
   mcp list
   ```

3. **Install and start a server:**
   ```bash
   mcp install github
   mcp start github
   ```

4. **Use MCP tools:**
   ```bash
   mcp use github search-repos "react"
   ```

## Commands

### Authentication
- `mcp login` - Login to MCP server
- `mcp logout` - Logout from MCP server

### Server Management
- `mcp list` - List available MCP servers
- `mcp install <server>` - Install an MCP server
- `mcp start <server>` - Start an MCP server
- `mcp stop <server>` - Stop an MCP server
- `mcp restart <server>` - Restart an MCP server
- `mcp status` - Show server status

### API Key Management
- `mcp keys` - List API keys
- `mcp create-key <name>` - Create new API key
- `mcp revoke-key <id>` - Revoke API key

### Tool Usage
- `mcp use <server> <tool> [args...]` - Execute MCP server tools

### Configuration
- `mcp config` - Show current configuration

## Available MCP Servers

- **github** - GitHub repository management, issues, PRs
- **brave** - Brave Search web and local search
- **puppeteer** - Browser automation
- **playwright** - Advanced browser testing
- **sequential** - Complex problem-solving workflows

## Examples

```bash
# Install and start GitHub MCP server
mcp install github
mcp start github

# Search GitHub repositories
mcp use github search-repos "machine learning"

# Create API key for external access
mcp create-key "my-app"

# Check server status
mcp status
```

## Configuration

Configuration is stored in `~/.mcp-cli/config.json`:

```json
{
  "serverUrl": "https://mcp.mvrx.com.au",
  "token": "your-auth-token",
  "user": "admin"
}
```

## Development

```bash
# Clone repository
git clone https://github.com/motionmavericks/mcp-cli.git
cd mcp-cli

# Install dependencies
npm install

# Link for local development
npm link

# Test CLI
mcp --help
```

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- GitHub: https://github.com/motionmavericks/mcp-cli/issues
- Server: https://mcp.mvrx.com.au
