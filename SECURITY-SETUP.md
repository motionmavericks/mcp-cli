# 🔒 SECURE DEPLOYMENT INSTRUCTIONS

## ⚠️ CRITICAL: Complete these steps BEFORE using the system

### 1. **Generate Secure Password Hash**

```bash
# Install bcrypt
npm install -g bcrypt-cli

# Generate hash for your password (replace 'your-secure-password')
bcrypt-cli hash 'your-secure-password' 12
```

### 2. **Set Environment Variables**

```bash
# In DigitalOcean App Platform or your deployment environment:
export JWT_SECRET="$(openssl rand -base64 64)"
export ADMIN_PASSWORD_HASH="$2b$12$..." # From step 1
export ALLOWED_ORIGINS="https://yourdomain.com,https://localhost:3000"
export NODE_ENV="production"
```

### 3. **Update DigitalOcean App**

Replace the current app spec with the secure server:

```bash
# Use secure-server.js instead of the inline code
# Add required dependencies:
npm install express-rate-limit helmet validator winston bcryptjs
```

### 4. **Update Package.json**

```json
{
  "dependencies": {
    "express": "^4.18.0",
    "jsonwebtoken": "^9.0.0",
    "bcryptjs": "^2.4.3",
    "express-rate-limit": "^6.7.0",
    "helmet": "^6.1.0",
    "validator": "^13.9.0",
    "winston": "^3.8.0",
    "uuid": "^9.0.0"
  }
}
```

### 5. **CLI Security Updates**

Replace `lib/auth.js` with `lib/secure-auth.js` in your CLI:

```bash
# Update client to use secure authentication
cp lib/secure-auth.js lib/auth.js
```

### 6. **Network Security**

#### Cloudflare Configuration:
```bash
# Add security headers
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

#### IP Whitelisting (Recommended):
```bash
# In DigitalOcean or Cloudflare, whitelist only your IP addresses
# Example: Only allow access from your office/home IPs
```

### 7. **Monitoring Setup**

#### Add Log Monitoring:
```bash
# Monitor security.log for:
# - Failed login attempts
# - Unusual access patterns
# - Rate limit violations
# - Authentication errors
```

#### Set up Alerts:
```bash
# Alert on:
# - More than 5 failed logins in 15 minutes
# - Access from unknown IPs
# - Invalid JWT tokens
# - Server errors
```

### 8. **Database Security (If Adding)**

```sql
-- Use encrypted database connections
-- Encrypt sensitive data at rest
-- Use separate database user with minimal permissions
-- Enable database audit logging
```

### 9. **Regular Security Tasks**

#### Daily:
- [ ] Review access logs
- [ ] Check for failed login attempts
- [ ] Monitor resource usage

#### Weekly:
- [ ] Update dependencies (`npm audit fix`)
- [ ] Review security logs
- [ ] Test backup recovery

#### Monthly:
- [ ] Rotate JWT secret
- [ ] Change admin password
- [ ] Security scan (`npm audit`)
- [ ] Review and update IP whitelist

### 10. **Emergency Procedures**

#### If Compromised:
1. **Immediately** change admin password
2. Rotate JWT secret (invalidates all sessions)
3. Review all logs for suspicious activity
4. Block suspicious IP addresses
5. Notify all users to re-authenticate

#### Security Incident Response:
1. Document the incident
2. Preserve logs and evidence
3. Assess impact and data exposure
4. Implement additional security measures
5. Update security procedures

## 🚫 **DO NOT:**

- ❌ Use default passwords
- ❌ Store credentials in code
- ❌ Allow public access
- ❌ Skip SSL certificate validation
- ❌ Ignore security logs
- ❌ Use the original insecure version

## ✅ **VERIFICATION CHECKLIST:**

- [ ] Password is bcrypt hashed (not plain text)
- [ ] JWT secret is randomly generated (64+ chars)
- [ ] CORS is configured for specific origins only
- [ ] Rate limiting is active
- [ ] SSL certificate is valid and enforced
- [ ] Logs are being written and monitored
- [ ] Repository is private
- [ ] All dependencies are up to date
- [ ] IP whitelisting is configured
- [ ] Backup and recovery procedures tested

## 📞 **Support:**

If you need help with secure deployment:
1. Review this checklist thoroughly
2. Test in a development environment first
3. Document your security configuration
4. Keep security logs for at least 90 days

**Remember: Security is an ongoing process, not a one-time setup!**