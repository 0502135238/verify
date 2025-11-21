import express from "express";
import cors from "cors"  
import fs from "fs";
import path from "path";

const app = express();
app.use(cors());
app.use(express.json());

const DATA_FILE = path.join(process.cwd(), "data.json");

function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    return { repos: [], stats: { totalIssuesDetected: 0, totalScans: 0 } };
  }
  return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// 📥 Report endpoint
app.post("/report", (req, res) => {
  const { repoName, sourceType, sourceUrl, issues, scannedAt } = req.body;
  const data = loadData();

  let repo = data.repos.find(r => r.repoName === repoName);
  if (!repo) {
    repo = { repoName, sourceType, sourceUrl, scans: [], verified: true };
    data.repos.push(repo);
    data.stats.totalScans++;
  }

  repo.scans.push({ issues, scannedAt });
  data.stats.totalIssuesDetected += issues.length;

  saveData(data);
  res.json({ ok: true, repo, stats: data.stats });
});

// 📊 Stats endpoint
app.get("/stats", (req, res) => {
  const data = loadData();
  res.json(data.stats);
});

// 📂 Repos endpoint
app.get("/repos", (req, res) => {
  const data = loadData();
  res.json(data.repos);
});

// 🗂️ Scans archive endpoint
app.get("/scans", (req, res) => {
  const data = loadData();
  const allScans = [];
  for (const repo of data.repos) {
    for (const scan of repo.scans) {
      allScans.push({
        repoName: repo.repoName,
        fileIssues: scan.issues,
        scannedAt: scan.scannedAt
      });
    }
  }
  // newest first
  allScans.sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt));
  res.json(allScans);
});

app.listen(4000, () => {
  console.log("✅ Verify API running on http://localhost:4000");
});