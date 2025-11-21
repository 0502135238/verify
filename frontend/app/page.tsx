"use client";
import { useEffect, useState } from "react";

export default function Home() {
  const [stats, setStats] = useState<any>(null);
  const [scans, setScans] = useState<any[]>([]);
  const [openIndex, setOpenIndex] = useState<number | null>(null);

  useEffect(() => {
    async function fetchData() {
      const statsRes = await fetch("http://localhost:4000/stats");
      const scansRes = await fetch("http://localhost:4000/scans");
      setStats(await statsRes.json());
      setScans(await scansRes.json());
    }
    fetchData();
  }, []);

  return (
    <main
      style={{
        backgroundColor: "#0d0d0d",
        color: "#00ff00",
        fontFamily: "monospace",
        minHeight: "100vh",
        padding: "2rem"
      }}
    >
      <h1 style={{ fontSize: "2rem", marginBottom: "1rem" }}>
        🔒 Verify Public Directory
      </h1>

      {stats && (
        <div style={{ marginBottom: "2rem" }}>
          <p>Total issues detected: {stats.totalIssuesDetected}</p>
          <p>Total scans: {stats.totalScans}</p>
        </div>
      )}

      <h2 style={{ marginBottom: "1rem" }}>Archive of Scans</h2>
      <ul style={{ listStyle: "none", padding: 0 }}>
        {scans.map((scan, index) => (
          <li
            key={index}
            style={{
              border: "1px solid #00ff00",
              marginBottom: "1rem",
              padding: "1rem",
              borderRadius: "4px"
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                cursor: "pointer"
              }}
              onClick={() => setOpenIndex(openIndex === index ? null : index)}
            >
              <span>
                📂 {scan.repoName} — scanned at {scan.scannedAt}
              </span>
              <span>{openIndex === index ? "▲ Hide" : "▼ Details"}</span>
            </div>

            {openIndex === index && (
              <ul style={{ marginTop: "1rem", paddingLeft: "1rem" }}>
                {scan.fileIssues.length === 0 ? (
                  <li>✅ No issues</li>
                ) : (
                  scan.fileIssues.map((issue: any, i: number) => (
                    <li key={i} style={{ marginBottom: "0.5rem" }}>
                      <strong style={{ color: getSeverityColor(issue.severity) }}>
                        {issue.severity}
                      </strong>{" "}
                      [{issue.category}] → {issue.message}
                      <div style={{ marginLeft: "1rem" }}>👉 {issue.hint}</div>
                    </li>
                  ))
                )}
              </ul>
            )}
          </li>
        ))}
      </ul>
    </main>
  );
}

// Helper to color severity labels
function getSeverityColor(severity: string) {
  switch (severity) {
    case "Critical":
      return "red";
    case "High":
      return "orange";
    case "Medium":
      return "cyan";
    case "Low":
      return "gray";
    default:
      return "white";
  }
}