#!/bin/bash

# MCP CLI Secure Deployment Script
# This script helps deploy the secure version to DigitalOcean

echo "🔒 MCP CLI Secure Deployment Helper"
echo "=================================="
echo ""

# Check if doctl is installed
if ! command -v doctl &> /dev/null; then
    echo "❌ doctl CLI not found. Please install it first:"
    echo "   https://docs.digitalocean.com/reference/doctl/how-to/install/"
    echo ""
    echo "Or use the DigitalOcean web console instead."
    exit 1
fi

# App ID
APP_ID="04752b50-c52a-43a9-b0d9-0b220bb70986"

echo "📋 Deployment Configuration:"
echo "   App ID: $APP_ID"
echo "   Repository: motionmavericks/mcp-cli"
echo "   Branch: main"
echo "   Server: secure-server.js"
echo ""

# Create app spec file
cat > app-spec.yml << EOF
name: mcp-api-server
services:
- name: api
  github:
    repo: motionmavericks/mcp-cli
    branch: main
  source_dir: /
  build_command: npm install
  run_command: node secure-server.js
  environment_slug: node-js
  instance_count: 1
  instance_size_slug: apps-s-2vcpu-4gb
  http_port: 3000
  envs:
  - key: NODE_ENV
    value: production
    scope: RUN_TIME
  - key: PORT
    value: "3000"
    scope: RUN_TIME
  - key: JWT_SECRET
    value: BfUVwTZAovzjbLl9v0zsRlpoIwbFmIvXSEvIX7p1l3RWUklX6NffSBfPaNab1uY1Wqn5qWjlrQ7KLwXbuZ391g==
    scope: RUN_TIME
  - key: ADMIN_PASSWORD_HASH
    value: \$6\$AdjmxNnlKsAVaz8g\$vl8eCH9iEh07R6WZBUiRXllxmgW1qsKGFgzHkb/A/L/qlwNM8oTYdLrV4xqFGSeeDp5pGlUQEZs7JsdTq7h8L1
    scope: RUN_TIME
  - key: ALLOWED_ORIGINS
    value: https://mcp.mvrx.com.au,https://localhost:3000
    scope: RUN_TIME
domains:
- domain: mcp.mvrx.com.au
  type: PRIMARY
region: syd
EOF

echo "📝 App specification created: app-spec.yml"
echo ""

# Authenticate check
echo "🔐 Checking authentication..."
if ! doctl auth list &> /dev/null; then
    echo "❌ Not authenticated with DigitalOcean."
    echo "   Run: doctl auth init"
    echo "   Then run this script again."
    exit 1
fi

echo "✅ Authenticated with DigitalOcean"
echo ""

# Deploy
echo "🚀 Deploying secure version..."
echo "   This will update the app to use the secure GitHub repository"
echo ""

read -p "Continue with deployment? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🔄 Updating app..."
    
    if doctl apps update $APP_ID --spec app-spec.yml; then
        echo ""
        echo "✅ Deployment initiated successfully!"
        echo ""
        echo "📊 Checking deployment status..."
        doctl apps get $APP_ID --format ID,Status,LiveURL
        echo ""
        echo "🔍 Monitor deployment:"
        echo "   doctl apps get $APP_ID"
        echo "   https://cloud.digitalocean.com/apps/$APP_ID"
        echo ""
        echo "🔑 New Login Credentials:"
        echo "   Password: SecureMCP2024!"
        echo "   URL: https://mcp.mvrx.com.au"
        echo ""
        echo "⚠️  Previous credentials are now invalid!"
    else
        echo "❌ Deployment failed. Check the error above."
        echo "   You may need to use the web console instead."
    fi
else
    echo "❌ Deployment cancelled."
fi

echo ""
echo "🔧 Manual Steps (if automated deployment fails):"
echo "1. Go to: https://cloud.digitalocean.com/apps"
echo "2. Click on: mcp-api-server"
echo "3. Click: Settings > Edit api component"
echo "4. Change source to GitHub: motionmavericks/mcp-cli"
echo "5. Set run command: node secure-server.js"
echo "6. Add the environment variables from app-spec.yml"
echo "7. Deploy"

# Cleanup
rm -f app-spec.yml

echo ""
echo "🏁 Deployment script completed."