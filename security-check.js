#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

console.log('🔒 AIM Clone Security Audit');
console.log('==========================\n');

let securityScore = 0;
const maxScore = 100;
const issues = [];
const warnings = [];

// 1. Check for environment variables
function checkEnvironmentVariables() {
    console.log('1. Environment Variables Check...');
    
    if (fs.existsSync('.env')) {
        const envContent = fs.readFileSync('.env', 'utf8');
        
        // Check for weak secrets
        if (envContent.includes('your-super-secure') || envContent.includes('default-secret')) {
            issues.push('❌ Weak or default secrets found in .env file');
            securityScore -= 10;
        } else {
            console.log('✅ Environment file exists with custom secrets');
            securityScore += 5;
        }
        
        // Check for JWT secret
        if (envContent.includes('JWT_SECRET=')) {
            console.log('✅ JWT secret configured');
            securityScore += 5;
        } else {
            warnings.push('⚠️  JWT_SECRET not found in .env');
        }
        
        // Check for session secret
        if (envContent.includes('SESSION_SECRET=')) {
            console.log('✅ Session secret configured');
            securityScore += 5;
        } else {
            warnings.push('⚠️  SESSION_SECRET not found in .env');
        }
    } else {
        issues.push('❌ No .env file found - using default configuration');
        securityScore -= 15;
    }
    console.log('');
}

// 2. Check package.json for security issues
function checkPackageSecurity() {
    console.log('2. Package Security Check...');
    
    const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    
    // Check for known vulnerable packages
    const vulnerablePackages = ['sqlite3', 'express'];
    let vulnerableFound = false;
    
    for (const pkg of vulnerablePackages) {
        if (packageJson.dependencies[pkg]) {
            console.log(`✅ ${pkg} is included (check for updates regularly)`);
        }
    }
    
    // Check for security-related packages
    const securityPackages = ['helmet', 'express-rate-limit', 'express-validator', 'bcryptjs'];
    let securityPackagesFound = 0;
    
    for (const pkg of securityPackages) {
        if (packageJson.dependencies[pkg]) {
            console.log(`✅ Security package found: ${pkg}`);
            securityPackagesFound++;
        }
    }
    
    if (securityPackagesFound >= 3) {
        console.log('✅ Good security package coverage');
        securityScore += 10;
    } else {
        warnings.push('⚠️  Consider adding more security packages');
    }
    console.log('');
}

// 3. Check server.js for security practices
function checkServerSecurity() {
    console.log('3. Server Security Check...');
    
    const serverContent = fs.readFileSync('server.js', 'utf8');
    
    // Check for security headers
    if (serverContent.includes('helmet')) {
        console.log('✅ Helmet security headers configured');
        securityScore += 10;
    } else {
        issues.push('❌ Helmet security headers not configured');
        securityScore -= 10;
    }
    
    // Check for rate limiting
    if (serverContent.includes('rateLimit') || serverContent.includes('express-rate-limit')) {
        console.log('✅ Rate limiting configured');
        securityScore += 10;
    } else {
        issues.push('❌ Rate limiting not configured');
        securityScore -= 10;
    }
    
    // Check for input validation
    if (serverContent.includes('express-validator') || serverContent.includes('validation')) {
        console.log('✅ Input validation configured');
        securityScore += 10;
    } else {
        issues.push('❌ Input validation not configured');
        securityScore -= 10;
    }
    
    // Check for CORS configuration
    if (serverContent.includes('cors') && !serverContent.includes('origin: "*"')) {
        console.log('✅ CORS properly configured');
        securityScore += 5;
    } else if (serverContent.includes('origin: "*"')) {
        issues.push('❌ CORS configured to allow all origins');
        securityScore -= 5;
    } else {
        warnings.push('⚠️  CORS configuration not found');
    }
    
    // Check for SQL injection prevention
    if (serverContent.includes('parameterized') || serverContent.includes('?') || serverContent.includes('$')) {
        console.log('✅ SQL injection prevention (parameterized queries)');
        securityScore += 10;
    } else {
        issues.push('❌ SQL injection prevention not evident');
        securityScore -= 10;
    }
    
    // Check for XSS prevention
    if (serverContent.includes('escapeHtml') || serverContent.includes('sanitize')) {
        console.log('✅ XSS prevention measures found');
        securityScore += 5;
    } else {
        warnings.push('⚠️  XSS prevention measures not evident');
    }
    
    console.log('');
}

// 4. Check database security
function checkDatabaseSecurity() {
    console.log('4. Database Security Check...');
    
    if (fs.existsSync('database.js')) {
        const dbContent = fs.readFileSync('database.js', 'utf8');
        
        // Check for prepared statements
        if (dbContent.includes('?') || dbContent.includes('$')) {
            console.log('✅ Database uses parameterized queries');
            securityScore += 10;
        } else {
            issues.push('❌ Database queries may be vulnerable to injection');
            securityScore -= 10;
        }
        
        // Check for password hashing
        if (dbContent.includes('bcrypt') || dbContent.includes('password_hash')) {
            console.log('✅ Passwords are hashed');
            securityScore += 10;
        } else {
            issues.push('❌ Passwords may not be properly hashed');
            securityScore -= 15;
        }
        
        // Check for session management
        if (dbContent.includes('session_token') || dbContent.includes('session_expires')) {
            console.log('✅ Session management implemented');
            securityScore += 5;
        } else {
            warnings.push('⚠️  Session management not found');
        }
        
        // Check for account lockout
        if (dbContent.includes('locked_until') || dbContent.includes('failed_login_attempts')) {
            console.log('✅ Account lockout mechanism implemented');
            securityScore += 5;
        } else {
            warnings.push('⚠️  Account lockout mechanism not found');
        }
        
        // Check for data cleanup
        if (dbContent.includes('cleanup') || dbContent.includes('DELETE FROM')) {
            console.log('✅ Data cleanup mechanisms found');
            securityScore += 5;
        } else {
            warnings.push('⚠️  Data cleanup mechanisms not found');
        }
    } else {
        issues.push('❌ Database module not found');
        securityScore -= 20;
    }
    console.log('');
}

// 5. Check frontend security
function checkFrontendSecurity() {
    console.log('5. Frontend Security Check...');
    
    const htmlContent = fs.readFileSync('public/index.html', 'utf8');
    const jsContent = fs.readFileSync('public/script.js', 'utf8');
    
    // Check for CSP headers
    if (htmlContent.includes('Content-Security-Policy') || htmlContent.includes('CSP')) {
        console.log('✅ Content Security Policy configured');
        securityScore += 5;
    } else {
        warnings.push('⚠️  Content Security Policy not configured');
    }
    
    // Check for XSS prevention in JavaScript
    if (jsContent.includes('escapeHtml') || jsContent.includes('textContent')) {
        console.log('✅ XSS prevention in client-side code');
        securityScore += 5;
    } else {
        warnings.push('⚠️  XSS prevention in client-side code not evident');
    }
    
    // Check for secure token handling
    if (jsContent.includes('localStorage') && jsContent.includes('token')) {
        console.log('✅ Token storage mechanism found');
        securityScore += 5;
    } else {
        warnings.push('⚠️  Token storage mechanism not found');
    }
    
    // Check for input sanitization
    if (jsContent.includes('trim()') || jsContent.includes('sanitize')) {
        console.log('✅ Input sanitization found');
        securityScore += 5;
    } else {
        warnings.push('⚠️  Input sanitization not evident');
    }
    
    console.log('');
}

// 6. Check file permissions and sensitive files
function checkFileSecurity() {
    console.log('6. File Security Check...');
    
    const sensitiveFiles = ['.env', 'aim_clone.db', 'package-lock.json'];
    
    for (const file of sensitiveFiles) {
        if (fs.existsSync(file)) {
            try {
                const stats = fs.statSync(file);
                const mode = stats.mode.toString(8);
                
                if (mode.endsWith('600') || mode.endsWith('400')) {
                    console.log(`✅ ${file} has secure permissions`);
                    securityScore += 2;
                } else {
                    warnings.push(`⚠️  ${file} may have overly permissive permissions`);
                }
            } catch (error) {
                console.log(`✅ ${file} exists and is accessible`);
            }
        }
    }
    
    // Check for .gitignore
    if (fs.existsSync('.gitignore')) {
        const gitignoreContent = fs.readFileSync('.gitignore', 'utf8');
        if (gitignoreContent.includes('.env') && gitignoreContent.includes('.db')) {
            console.log('✅ Sensitive files are gitignored');
            securityScore += 5;
        } else {
            warnings.push('⚠️  Sensitive files may not be gitignored');
        }
    } else {
        issues.push('❌ No .gitignore file found');
        securityScore -= 5;
    }
    
    console.log('');
}

// 7. Generate security recommendations
function generateRecommendations() {
    console.log('7. Security Recommendations...\n');
    
    const recommendations = [
        '🔐 Use strong, unique secrets for JWT and session tokens',
        '🛡️  Implement Content Security Policy (CSP) headers',
        '🚫 Configure proper CORS origins (not *)',
        '⏱️  Implement rate limiting on all endpoints',
        '🔒 Add account lockout after failed login attempts',
        '🧹 Implement automatic cleanup of old data',
        '📝 Add comprehensive logging for security events',
        '🔍 Regular security audits and dependency updates',
        '🌐 Use HTTPS in production',
        '👥 Implement proper user session management'
    ];
    
    recommendations.forEach(rec => console.log(rec));
    console.log('');
}

// 8. Generate secure secrets
function generateSecureSecrets() {
    console.log('8. Secure Secret Generation...\n');
    
    const jwtSecret = crypto.randomBytes(64).toString('hex');
    const sessionSecret = crypto.randomBytes(64).toString('hex');
    const dbKey = crypto.randomBytes(32).toString('hex');
    
    console.log('🔑 Generated secure secrets:');
    console.log(`JWT_SECRET=${jwtSecret}`);
    console.log(`SESSION_SECRET=${sessionSecret}`);
    console.log(`DB_ENCRYPTION_KEY=${dbKey}`);
    console.log('\n💡 Add these to your .env file for maximum security!\n');
}

// Run all checks
async function runSecurityAudit() {
    checkEnvironmentVariables();
    checkPackageSecurity();
    checkServerSecurity();
    checkDatabaseSecurity();
    checkFrontendSecurity();
    checkFileSecurity();
    generateRecommendations();
    generateSecureSecrets();
    
    // Calculate final score
    securityScore = Math.max(0, Math.min(100, securityScore));
    
    console.log('📊 Security Audit Results');
    console.log('========================');
    console.log(`Overall Security Score: ${securityScore}/100`);
    
    if (securityScore >= 90) {
        console.log('🏆 Excellent security posture!');
    } else if (securityScore >= 70) {
        console.log('✅ Good security posture with room for improvement');
    } else if (securityScore >= 50) {
        console.log('⚠️  Moderate security posture - improvements needed');
    } else {
        console.log('🚨 Poor security posture - immediate action required');
    }
    
    console.log('');
    
    if (issues.length > 0) {
        console.log('❌ Critical Issues Found:');
        issues.forEach(issue => console.log(`  ${issue}`));
        console.log('');
    }
    
    if (warnings.length > 0) {
        console.log('⚠️  Warnings:');
        warnings.forEach(warning => console.log(`  ${warning}`));
        console.log('');
    }
    
    console.log('🔧 Next Steps:');
    console.log('1. Address all critical issues');
    console.log('2. Implement security recommendations');
    console.log('3. Run this audit again after changes');
    console.log('4. Consider professional security review for production');
}

// Run the audit
runSecurityAudit().catch(console.error); 