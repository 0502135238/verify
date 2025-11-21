#!/usr/bin/env node
import fs from "fs";
import path from "path";
import fetch from "node-fetch";
import os from "os";
import { execSync } from "child_process";

const API_URL = "http://localhost:4000";
// Debugging helper: normalize common errors
function translateError(err) {
  const msg = err?.message ? String(err.message) : String(err);

  if (msg.includes("ECONNREFUSED")) {
    return {
      category: "Database",
      severity: "Critical",
      message: "Database connection refused",
      hint: "Make sure your DB server is running and connection string is correct."
    };
  }
  if (msg.includes("MODULE_NOT_FOUND")) {
    return {
      category: "Dependencies",
      severity: "High",
      message: "Module not found",
      hint: "Run `npm install` or check your import path."
    };
  }
  if (msg.includes("SyntaxError")) {
    return {
      category: "Code",
      severity: "High",
      message: "Syntax error in code",
      hint: "Check the line mentioned in the error for typos or missing brackets."
    };
  }

  return {
    category: "Errors",
    severity: "Medium",
    message: msg,
    hint: "Check logs and stack trace for more details."
  };
}

// Capture uncaught runtime errors and show them in Verify style
process.on("uncaughtException", (err) => {
  const issue = translateError(err);
  console.log("\n🔴 Runtime Error Detected:");
  printIssues([issue]);
});

process.on("unhandledRejection", (reason) => {
  const issue = translateError(reason);
  console.log("\n🔴 Unhandled Promise Rejection:");
  printIssues([issue]);
});
// Helper: scan one file
function scanFile(filePath) {
  const issues = [];
  const lower = path.basename(filePath).toLowerCase();

  // --- Filename checks ---
  if (lower.includes(".env")) {
    issues.push({
      category: "Secrets",
      severity: "Critical",
      message: `Sensitive .env file detected: ${filePath}`,
      hint: "Never commit .env files. Use environment variables or secret managers."
    });
  }
  if (lower.includes("id_rsa") || lower.endsWith(".pem")) {
    issues.push({
      category: "Secrets",
      severity: "Critical",
      message: `Private key detected: ${filePath}`,
      hint: "Remove private keys from repos. Store them securely outside version control."
    });
  }
  if (lower === "config.js" || lower === "config.json") {
    issues.push({
      category: "Secrets",
      severity: "High",
      message: `Config file may contain secrets: ${filePath}`,
      hint: "Check config files for hardcoded credentials. Move sensitive values to env vars."
    });
  }
  if (lower.includes("secret") || lower.includes("password")) {
    issues.push({
      category: "Secrets",
      severity: "High",
      message: `Potential secret in filename: ${filePath}`,
      hint: "Avoid naming files with 'secret' or 'password'. It signals sensitive content."
    });
  }
  if (lower.endsWith(".log")) {
    issues.push({
      category: "Logging",
      severity: "Low",
      message: `Debug log file detected: ${filePath}`,
      hint: "Logs may leak sensitive data. Avoid committing them."
    });
  }

  // --- Content checks ---
  try {
    const content = fs.readFileSync(filePath, "utf8");

    // Secrets
    if (content.match(/AKIA[0-9A-Z]{16}/)) issues.push({
      category: "Secrets",
      severity: "Critical",
      message: `AWS Access Key found in ${filePath}`,
      hint: "Rotate AWS keys and use IAM roles instead of hardcoding."
    });
    if (content.includes("AWS_SECRET_KEY")) issues.push({
      category: "Secrets",
      severity: "Critical",
      message: `AWS secret key reference in ${filePath}`,
      hint: "Remove AWS secrets from code. Use environment variables or secret managers."
    });
    if (content.match(/password\s*=\s*['"].+['"]/i)) issues.push({
      category: "Secrets",
      severity: "Critical",
      message: `Hardcoded password found in ${filePath}`,
      hint: "Never hardcode passwords. Use env vars or secure vaults."
    });
    if (content.includes("BEGIN PRIVATE KEY")) issues.push({
      category: "Secrets",
      severity: "Critical",
      message: `Private key content found in ${filePath}`,
      hint: "Remove private keys from source code. Store them securely."
    });
    if (content.match(/api[_-]?key\s*=\s*['"].+['"]/i)) issues.push({
      category: "Secrets",
      severity: "Critical",
      message: `API key found in ${filePath}`,
      hint: "Rotate API keys and store them outside code."
    });
    if (content.match(/sk_live_[0-9a-zA-Z]{24,}/)) issues.push({
      category: "Secrets",
      severity: "Critical",
      message: `Stripe live secret key found in ${filePath}`,
      hint: "Use test keys in dev. Never commit live keys."
    });
    if (content.match(/mongodb:\/\/\S+/i)) issues.push({
      category: "Secrets",
      severity: "High",
      message: `MongoDB connection string found in ${filePath}`,
      hint: "Move DB connection strings to env vars."
    });
    if (content.match(/postgres:\/\/\S+/i)) issues.push({
      category: "Secrets",
      severity: "High",
      message: `Postgres connection string found in ${filePath}`,
      hint: "Store DB credentials securely outside code."
    });
    if (content.match(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/)) issues.push({
      category: "Secrets",
      severity: "High",
      message: `JWT token found in ${filePath}`,
      hint: "Never commit JWTs. Generate them dynamically."
    });

    // Weak crypto usage
    if (content.match(/crypto\.createHash\(["'](md5|sha1)["']\)/i)) {
      issues.push({
        category: "Crypto",
        severity: "High",
        message: `Weak crypto algorithm (MD5/SHA1) used in ${filePath}`,
        hint: "Use bcrypt, Argon2, or SHA256+salt for secure hashing."
      });
    }
    if (content.match(/crypto\.createHash\(["']sha256["']\)/i)) {
      issues.push({
        category: "Crypto",
        severity: "Medium",
        message: `Plain SHA256 used for password hashing in ${filePath}`,
        hint: "Use adaptive algorithms like bcrypt or Argon2 for password storage."
      });
    }

    // Unhardened cookies
    if (content.match(/res\.cookie\(/i) && !content.includes("HttpOnly")) {
      issues.push({
        category: "Cookies",
        severity: "High",
        message: `Cookie set without HttpOnly flag in ${filePath}`,
        hint: "Add { httpOnly: true } to cookies to prevent XSS attacks."
      });
    }
    if (content.match(/res\.cookie\(/i) && !content.includes("Secure")) {
      issues.push({
        category: "Cookies",
        severity: "High",
        message: `Cookie set without Secure flag in ${filePath}`,
        hint: "Add { secure: true } to cookies to enforce HTTPS."
      });
    }

    // Default credentials
    if (content.match(/(admin|root)\s*[:=]\s*(admin|password|1234)/i)) {
      issues.push({
        category: "Credentials",
        severity: "Critical",
        message: `Default credential found in ${filePath}`,
        hint: "Remove default creds. Enforce strong unique passwords."
      });
    }

    // Suspicious logging
    if (content.match(/console\.log\(.+password/i) || content.match(/console\.log\(.+token/i)) {
      issues.push({
        category: "Logging",
        severity: "Medium",
        message: `Sensitive data logged in ${filePath}`,
        hint: "Avoid logging passwords or tokens. Use masked logs."
      });
    }

    // Public cloud configs
    if (content.match(/s3:\/\/\S+/i) && !content.includes("private")) {
      issues.push({
        category: "Cloud",
        severity: "High",
        message: `Potential public S3 bucket reference in ${filePath}`,
        hint: "Ensure S3 buckets are private and access‑controlled."
      });
    }

    // Error messages leaking info
    if (content.match(/Error:/i) && content.match(/at\s+\S+/)) {
      issues.push({
        category: "Errors",
        severity: "Medium",
        message: `Stack trace exposure risk in ${filePath}`,
        hint: "Disable stack traces in production. Use generic error messages."
      });
    }
  } catch {
    // Ignore binary/unreadable files
  }

  return issues;
}

// 🔍 Scan for common developer mistakes (supports file or folder, recursive)
function scanForSecrets(targetPath) {
  const issues = [];

  function walk(currentPath) {
    let stats;
    try {
      stats = fs.statSync(currentPath);
    } catch {
      return;
    }

    if (stats.isFile()) {
      issues.push(...scanFile(currentPath));
    } else if (stats.isDirectory()) {
      const base = path.basename(currentPath);
      // Skip vendor folders
      if (["node_modules", ".git", "dist"].includes(base)) {
        return;
      }
      const files = fs.readdirSync(currentPath);
      for (const file of files) {
        walk(path.join(currentPath, file));
      }
    }
  }

  walk(targetPath);
  return issues;
}

// 📤 Send results to API
async function postReport(repoName, issues, sourceType = "local", sourceUrl = null) {
  try {
    const res = await fetch(`${API_URL}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repoName,
        sourceType,
        sourceUrl,
        issues,
        scannedAt: new Date().toISOString()
      })
    });
    const data = await res.json();
    console.log("✅ Synced to Verify API:", data);
  } catch (err) {
    console.error("❌ Failed to sync with API:", err.message);
  }
}

// 📊 Show current stats
async function showStatus() {
  try {
    const res = await fetch(`${API_URL}/stats`);
    const stats = await res.json();
    console.log("📊 Current stats:", stats);
  } catch (err) {
    console.error("❌ Failed to fetch stats:", err.message);
  }
}

// 📥 Scan GitHub repo
async function scanGithubRepo(url) {
  try {
    const tmpDir = path.join(os.tmpdir(), `verify-${Date.now()}`);
    console.log(`⬇️ Cloning ${url} into ${tmpDir}...`);
    execSync(`git clone --depth=1 ${url} ${tmpDir}`, { stdio: "ignore" });

    const issues = scanForSecrets(tmpDir);
    console.log("🔍 Scan complete:", issues);

    await postReport(path.basename(url), issues, "github", url);
  } catch (err) {
    console.error("❌ Failed to scan GitHub repo:", err.message);
  }
}
function printIssues(issues) {
  if (!issues.length) {
    console.log("✅ No issues found!");
    return;
  }

  const severityColors = {
    Critical: "\x1b[31m", // red
    High: "\x1b[33m",     // yellow
    Medium: "\x1b[36m",   // cyan
    Low: "\x1b[37m"       // gray
  };

  for (const issue of issues) {
    const color = severityColors[issue.severity] || "\x1b[0m";
    console.log(`${color}${issue.severity} [${issue.category}] → ${issue.message}\x1b[0m`);
    console.log(`   👉 ${issue.hint}`);
  }
}

// 🎯 CLI entry point
const args = process.argv.slice(2);
const command = args[0];

(async () => {
  if (command === "scan") {
    const target = args[1] || ".";
    const issues = scanForSecrets(target);
    printIssues(issues);
    const repoName = path.basename(path.resolve(target));
    await postReport(repoName, issues, "local", null);
  } else if (command === "status") {
    await showStatus();
  } else if (command === "scan-repo") {
    const url = args[1];
    if (!url) {
      console.log("Usage: vfy scan-repo <github-url>");
      process.exit(1);
    }
    await scanGithubRepo(url);
  } else {
    console.log("Usage:");
    console.log("  vfy scan [folder|file]     → scan a local folder or single file (recursive)");
    console.log("  vfy status                 → show totals");
    console.log("  vfy scan-repo <url>        → scan a GitHub repo");
  }
})();