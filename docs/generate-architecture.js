const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, WidthType, ShadingType,
  LevelFormat, PageNumber, PageBreak,
  Header, Footer
} = require('docx');
const fs = require('fs');
const path = require('path');

// ── Colours ──────────────────────────────────────────────────────────────────
const C = {
  purple: "6B48C8",  // brand primary
  purpleLight: "EDE9FA",
  teal: "0F6E56",
  tealLight: "D4F0E7",
  green: "3B6D11",
  greenLight: "EAF3DE",
  amber: "854F0B",
  amberLight: "FDF3DC",
  coral: "993C1D",
  coralLight: "FAF0EC",
  blue: "185FA5",
  blueLight: "E6F1FB",
  gray: "444441",
  grayLight: "F1EFE8",
  red: "A32D2D",
  redLight: "FCEBEB",
  white: "FFFFFF",
  black: "1A1A1A",
  border: "D0CEC8",
};

// ── Helpers ───────────────────────────────────────────────────────────────────
const border = (color = C.border) => ({ style: BorderStyle.SINGLE, size: 1, color });
const borders = (color) => ({ top: border(color), bottom: border(color), left: border(color), right: border(color) });
const noBorder = () => ({ style: BorderStyle.NONE, size: 0, color: "FFFFFF" });
const noBorders = () => ({ top: noBorder(), bottom: noBorder(), left: noBorder(), right: noBorder() });
const spacing = (before = 0, after = 0) => ({ before, after });
const cellMargins = { top: 100, bottom: 100, left: 160, right: 160 };

const h = (text, level) => new Paragraph({
  heading: level,
  children: [new TextRun({ text, bold: true })],
  spacing: spacing(320, 160),
});

const p = (text, opts = {}) => new Paragraph({
  children: [new TextRun({ text, ...opts })],
  spacing: spacing(0, 160),
});

const gap = (size = 160) => new Paragraph({ children: [], spacing: spacing(0, size) });
const bullet = (text, level = 0) => new Paragraph({
  numbering: { reference: "bullets", level },
  children: [new TextRun({ text })],
  spacing: spacing(0, 80),
});
const numbered = (text, level = 0) => new Paragraph({
  numbering: { reference: "numbers", level },
  children: [new TextRun({ text })],
  spacing: spacing(0, 80),
});

const divider = () => new Paragraph({
  children: [],
  border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: C.purple, space: 1 } },
  spacing: spacing(0, 240),
});

// Code block
const codeBlock = (lines) => {
  const rows = lines.map(line =>
    new TableRow({
      children: [new TableCell({
        borders: noBorders(),
        margins: { top: 40, bottom: 40, left: 200, right: 200 },
        width: { size: 9360, type: WidthType.DXA },
        children: [new Paragraph({
          children: [new TextRun({ text: line, font: "Courier New", size: 18, color: C.purple })],
          spacing: spacing(0, 0),
        })],
      })]
    })
  );
  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [9360],
    borders: {
      top: border(C.purple),
      bottom: border(C.purple),
      left: border(C.purple),
      right: border(C.purple),
      insideH: noBorder(),
      insideV: noBorder(),
    },
    shading: { fill: "F7F5FF", type: ShadingType.CLEAR },
    rows,
  });
};

// Coloured callout box
const callout = (label, text, fillColor, labelColor) => new Table({
  width: { size: 9360, type: WidthType.DXA },
  columnWidths: [9360],
  borders: {
    top: border(labelColor), bottom: border(labelColor),
    left: { style: BorderStyle.SINGLE, size: 12, color: labelColor },
    right: border(labelColor),
    insideH: noBorder(), insideV: noBorder(),
  },
  rows: [
    new TableRow({ children: [new TableCell({
      shading: { fill: fillColor, type: ShadingType.CLEAR },
      borders: noBorders(),
      margins: cellMargins,
      width: { size: 9360, type: WidthType.DXA },
      children: [
        new Paragraph({ children: [new TextRun({ text: label, bold: true, color: labelColor, size: 20 })], spacing: spacing(0, 60) }),
        new Paragraph({ children: [new TextRun({ text, size: 20 })], spacing: spacing(0, 0) }),
      ],
    })]})
  ],
});

// Generic 2-col table
const twoColTable = (rows, headerFill = C.purple, textColor = C.white) => {
  const tableRows = rows.map((row, i) => new TableRow({
    children: row.map((cell, j) => new TableCell({
      borders: borders(C.border),
      shading: { fill: i === 0 ? headerFill : (i % 2 === 0 ? C.grayLight : C.white), type: ShadingType.CLEAR },
      margins: cellMargins,
      width: { size: j === 0 ? 2800 : 6560, type: WidthType.DXA },
      children: [new Paragraph({
        children: [new TextRun({
          text: cell,
          bold: i === 0,
          color: i === 0 ? textColor : C.black,
          size: 20,
        })],
        spacing: spacing(0, 0),
      })],
    })),
  }));
  return new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: [2800, 6560], rows: tableRows });
};

// Priority table (4 cols)
const priorityTable = (rows) => {
  const cols = [1200, 3000, 2000, 3160];
  const tableRows = rows.map((row, i) => new TableRow({
    children: row.map((cell, j) => {
      let fill = i === 0 ? C.purple : C.white;
      if (i > 0 && j === 2) {
        if (cell.includes("30 min")) fill = C.greenLight;
        else if (cell.includes("1 hr") || cell.includes("2 hr")) fill = C.tealLight;
        else if (cell.includes("3 hr") || cell.includes("4 hr")) fill = C.amberLight;
      }
      return new TableCell({
        borders: borders(C.border),
        shading: { fill, type: ShadingType.CLEAR },
        margins: cellMargins,
        width: { size: cols[j], type: WidthType.DXA },
        children: [new Paragraph({
          children: [new TextRun({ text: cell, bold: i === 0, color: i === 0 ? C.white : C.black, size: 20 })],
          spacing: spacing(0, 0),
        })],
      });
    }),
  }));
  return new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: cols, rows: tableRows });
};

// ── Document ──────────────────────────────────────────────────────────────────
const doc = new Document({
  numbering: {
    config: [
      { reference: "bullets", levels: [
        { level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } },
        { level: 1, format: LevelFormat.BULLET, text: "◦", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 1080, hanging: 360 } } } },
      ]},
      { reference: "numbers", levels: [
        { level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } },
      ]},
    ],
  },
  styles: {
    default: { document: { run: { font: "Arial", size: 22, color: C.black } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 40, bold: true, font: "Arial", color: C.purple },
        paragraph: { spacing: { before: 480, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 30, bold: true, font: "Arial", color: C.purple },
        paragraph: { spacing: { before: 400, after: 160 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 24, bold: true, font: "Arial", color: C.gray },
        paragraph: { spacing: { before: 320, after: 120 }, outlineLevel: 2 } },
    ],
  },
  sections: [{
    properties: {
      page: {
        size: { width: 12240, height: 15840 },
        margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
      },
    },
    headers: {
      default: new Header({
        children: [new Table({
          width: { size: 9360, type: WidthType.DXA },
          columnWidths: [6000, 3360],
          borders: { top: noBorder(), left: noBorder(), right: noBorder(), insideH: noBorder(), insideV: noBorder(),
            bottom: { style: BorderStyle.SINGLE, size: 4, color: C.purple } },
          rows: [new TableRow({ children: [
            new TableCell({ borders: noBorders(), margins: { top: 80, bottom: 80, left: 0, right: 0 }, width: { size: 6000, type: WidthType.DXA },
              children: [new Paragraph({ children: [new TextRun({ text: "SITE SENTINEL AI", bold: true, color: C.purple, size: 20 })] })] }),
            new TableCell({ borders: noBorders(), margins: { top: 80, bottom: 80, left: 0, right: 0 }, width: { size: 3360, type: WidthType.DXA },
              children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: "Hackathon Architecture v2.0", color: C.gray, size: 18 })] })] }),
          ]})]
        })],
      }),
    },
    footers: {
      default: new Footer({
        children: [new Table({
          width: { size: 9360, type: WidthType.DXA },
          columnWidths: [6000, 3360],
          borders: { bottom: noBorder(), left: noBorder(), right: noBorder(), insideH: noBorder(), insideV: noBorder(),
            top: { style: BorderStyle.SINGLE, size: 4, color: C.border } },
          rows: [new TableRow({ children: [
            new TableCell({ borders: noBorders(), margins: { top: 80, bottom: 0, left: 0, right: 0 }, width: { size: 6000, type: WidthType.DXA },
              children: [new Paragraph({ children: [new TextRun({ text: "Confidential — Internal Hackathon Use Only", color: C.gray, size: 16 })] })] }),
            new TableCell({ borders: noBorders(), margins: { top: 80, bottom: 0, left: 0, right: 0 }, width: { size: 3360, type: WidthType.DXA },
              children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [
                new TextRun({ text: "Page ", color: C.gray, size: 16 }),
                new TextRun({ children: [PageNumber.CURRENT], color: C.gray, size: 16 }),
                new TextRun({ text: " of ", color: C.gray, size: 16 }),
                new TextRun({ children: [PageNumber.TOTAL_PAGES], color: C.gray, size: 16 }),
              ]})] }),
          ]})]
        })],
      }),
    },
    children: [

      // ── COVER ─────────────────────────────────────────────────────────────
      gap(1440),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "SITE SENTINEL AI", bold: true, size: 64, color: C.purple, font: "Arial" })],
        spacing: spacing(0, 120),
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "Hackathon Architecture Document", size: 36, color: C.gray, font: "Arial" })],
        spacing: spacing(0, 80),
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "Version 2.0  ·  Production-Grade Design  ·  Global Tech Hackathon 2026", size: 22, color: C.gray, font: "Arial" })],
        spacing: spacing(0, 480),
      }),

      // Cover summary box
      new Table({
        width: { size: 7200, type: WidthType.DXA },
        columnWidths: [7200],
        borders: { top: border(C.purple), bottom: border(C.purple), left: { style: BorderStyle.SINGLE, size: 16, color: C.purple }, right: border(C.purple), insideH: noBorder(), insideV: noBorder() },
        rows: [new TableRow({ children: [new TableCell({
          shading: { fill: C.purpleLight, type: ShadingType.CLEAR },
          borders: noBorders(),
          margins: { top: 240, bottom: 240, left: 360, right: 360 },
          width: { size: 7200, type: WidthType.DXA },
          children: [
            new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Real-time AI web safety scanner", bold: true, size: 26, color: C.purple })], spacing: spacing(0, 120) }),
            new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Chrome MV3 Extension  ·  FastAPI Backend  ·  Supabase Intelligence Layer  ·  Gemini 2.5 Flash (Vision + Text)", size: 20, color: C.gray })], spacing: spacing(0, 0) }),
          ],
        })]})],
      }),

      gap(2880),
      new Paragraph({ children: [new PageBreak()] }),

      // ── 1. EXECUTIVE SUMMARY ──────────────────────────────────────────────
      h("1. Executive Summary", HeadingLevel.HEADING_1),
      p("Site Sentinel AI is a Chrome browser extension that analyzes any website in real time for phishing threats, privacy risks, and malicious behavior. It combines deterministic heuristic scoring with Google Gemini 2.5 Flash AI — including visual screenshot analysis — and backs every scan with a crowdsourced domain intelligence layer powered by Supabase."),
      gap(),
      p("This document describes the complete production-grade architecture for the hackathon submission: every module, every database table, every API endpoint, every deployment step, and the exact 60-second demo script judges will see."),
      gap(),

      callout(
        "WINNING HYPOTHESIS",
        "Most teams will build a website scanner that sends a URL to an LLM. Site Sentinel AI is different in three ways: (1) Gemini Vision reads a screenshot and describes visual deception the text alone cannot catch, (2) every scan is persisted and crowd-aggregated so domain reputation compounds over time, and (3) every analysis generates a shareable public URL — a live artifact judges can keep after the hackathon ends.",
        C.purpleLight,
        C.purple
      ),

      gap(320),
      divider(),

      // ── 2. SYSTEM OVERVIEW ────────────────────────────────────────────────
      h("2. System Overview", HeadingLevel.HEADING_1),
      p("Site Sentinel AI is a client-server-database system with four distinct tiers. Each tier has a single responsibility and communicates over well-defined interfaces."),
      gap(),

      twoColTable([
        ["Tier", "Responsibility"],
        ["Browser (Chrome MV3)", "Collect DOM telemetry, network telemetry, and a page screenshot. Render the analysis result in the popup UI."],
        ["FastAPI Backend", "Receive telemetry, run heuristic pre-scoring, call external reputation APIs, invoke Gemini AI with structured output, persist results to Supabase, return combined verdict."],
        ["Supabase Intelligence Layer", "Store domain reputation, scan reports, and phishing infrastructure graphs. Serve crowdsourced intelligence on subsequent scans of the same domain."],
        ["Output Surfaces", "Extension popup with animated trust score ring. Shareable public report page. D3 threat network graph. Live admin dashboard."],
      ]),

      gap(320),
      divider(),

      // ── 3. ARCHITECTURE DIAGRAM (ASCII) ───────────────────────────────────
      h("3. Architecture Data Flow", HeadingLevel.HEADING_1),
      p("The following diagram shows the complete data flow from browser through to output surfaces."),
      gap(),

      codeBlock([
        "USER OPENS EXTENSION POPUP",
        "         │",
        "         ▼",
        "┌─────────────────────────────────────────────────────────────┐",
        "│  CHROME EXTENSION (MV3)                                     │",
        "│                                                             │",
        "│  content.js ──► DOM signals, forms, keywords, links        │",
        "│  background.js ► Network map, trackers, ad scripts         │",
        "│  offscreen.js ──► Page screenshot (base64 PNG)             │",
        "│  popup.js ──────► React UI, trust ring, verdict card       │",
        "│                                                             │",
        "│  USER CLICKS ▶ ANALYZE                                     │",
        "│         │                                                   │",
        "│         ▼ POST /analyze (telemetry + screenshot)           │",
        "└─────────┬───────────────────────────────────────────────────┘",
        "          │",
        "          ▼",
        "┌─────────────────────────────────────────────────────────────┐",
        "│  FASTAPI BACKEND (Railway / Render)                         │",
        "│                                                             │",
        "│  reputation.py ─► VirusTotal + URLScan + AbuseIPDB        │",
        "│  scorer.py ─────► Weighted heuristic pre-score (0–100)    │",
        "│  vision.py ─────► Gemini Vision screenshot analysis        │",
        "│  prompts.py ────► Gemini text analysis (JSON schema mode)  │",
        "│  report_gen.py ─► Write scan to Supabase, return token     │",
        "│                                                             │",
        "│  Returns { pre_score, reputation, ai_verdict, share_token }│",
        "└─────────┬───────────────────────────────────────────────────┘",
        "          │",
        "          ▼",
        "┌─────────────────────────────────────────────────────────────┐",
        "│  SUPABASE (PostgreSQL + pgvector + Edge Functions)          │",
        "│                                                             │",
        "│  domain_reputation  ◄──► aggregate_domain (Edge Fn)       │",
        "│  scan_reports       ◄──► embed_report (Edge Fn, pgvector) │",
        "│  phishing_network   ◄──► graph infrastructure clusters     │",
        "│                                                             │",
        "└─────────┬───────────────────────────────────────────────────┘",
        "          │",
        "          ▼",
        "┌─────────────────────────────────────────────────────────────┐",
        "│  OUTPUT SURFACES                                            │",
        "│                                                             │",
        "│  Extension Popup  ──► Trust ring, verdict, crowd badge     │",
        "│  sentinel.app/r/{token} ► Shareable public report page     │",
        "│  /graph ────────────► D3 phishing network visualizer       │",
        "│  /dashboard ────────► Live metrics for judge demo          │",
        "└─────────────────────────────────────────────────────────────┘",
      ]),

      gap(320),
      divider(),

      // ── 4. CHROME EXTENSION ───────────────────────────────────────────────
      h("4. Chrome Extension (Browser Tier)", HeadingLevel.HEADING_1),

      h("4.1 content.js — DOM Telemetry Collector", HeadingLevel.HEADING_2),
      p("Injected into every page via manifest match_all_urls. Crawls the live DOM and returns a structured telemetry object when queried by popup.js."),
      gap(),
      p("Collects the following signals:"),
      bullet("HTTPS status, certificate issuer, domain age estimate"),
      bullet("All form elements: action URLs, input field types (email, password, tel, cc-number, dob)"),
      bullet("External link ratio vs internal links"),
      bullet("Presence of privacy policy, terms of service, contact page links"),
      bullet("Phishing keyword density: urgency words, brand impersonation strings, threat language"),
      bullet("Shortened URL presence (bit.ly, tinyurl, t.co, etc.)"),
      bullet("Cookie count and SameSite policy"),
      bullet("navigator.permissions state for geolocation and notifications"),
      gap(),

      h("4.2 background.js — Network Telemetry Service Worker", HeadingLevel.HEADING_2),
      p("Persistent service worker using chrome.webRequest.onBeforeRequest to intercept all network requests for the active tab. Classifies third-party requests into categories using domain pattern matching."),
      gap(),
      p("Produces per-tab network telemetry object:"),
      bullet("tracker_count: domains matching known tracker lists"),
      bullet("analytics_count: GA, Mixpanel, Amplitude, Segment, etc."),
      bullet("ad_count: advertising networks"),
      bullet("third_party_domains: unique external domain list"),
      bullet("request_total: total outbound requests"),
      gap(),

      h("4.3 offscreen.js — Screenshot Capture (NEW)", HeadingLevel.HEADING_2),
      callout(
        "NEW MODULE",
        "This is the feature that will win the hackathon. No competitor team will have visual AI analysis of the page layout. offscreen.js uses the Chrome Offscreen Documents API to capture a PNG screenshot of the active tab and pass it to the backend as base64. Gemini Vision then describes exactly which visual elements look suspicious — fake login boxes, misleading branding, urgency banners.",
        C.greenLight,
        C.green
      ),
      gap(),
      p("Implementation steps:"),
      numbered("Register offscreen.html in manifest.json under offscreen permissions"),
      numbered("Call chrome.offscreen.createDocument() from background.js when popup requests a scan"),
      numbered("Use chrome.tabs.captureVisibleTab() inside the offscreen context to get base64 PNG"),
      numbered("Return the base64 string to popup.js via chrome.runtime.sendMessage"),
      numbered("popup.js bundles the screenshot into the POST /analyze request body"),
      gap(),

      h("4.4 popup.js + React UI — Trust Ring (REBUILT)", HeadingLevel.HEADING_2),
      p("The popup is rebuilt as a React application (Vite + React 18). Key UI components:"),
      gap(),
      bullet("TrustRing.jsx — SVG animated circular arc. Fills green (75–100), amber (40–74), or red (0–39) as the score resolves. This is the hero visual judges see first."),
      bullet("VerdictCard.jsx — SAFE / SUSPICIOUS / DANGEROUS badge with AI-generated one-line summary"),
      bullet("CrowdBadge.jsx — 'Seen by N users, M flagged this domain' — pulled from domain_reputation"),
      bullet("RiskFactorList.jsx — collapsible accordion per risk category (Phishing, Privacy, Network, Visual)"),
      bullet("ScreenshotInsights.jsx — renders Gemini Vision's visual observations as a highlighted list"),
      bullet("ShareButton.jsx — copies sentinel.app/r/{token} to clipboard with one click"),
      gap(),

      codeBlock([
        "// popup/src/components/TrustRing.jsx (skeleton)",
        "const TrustRing = ({ score }) => {",
        "  const r = 54, circ = 2 * Math.PI * r;",
        "  const fill = score >= 75 ? '#0F6E56' : score >= 40 ? '#854F0B' : '#A32D2D';",
        "  const dash = (score / 100) * circ;",
        "  return (",
        "    <svg viewBox='0 0 120 120' width={120} height={120}>",
        "      <circle cx={60} cy={60} r={r} fill='none' stroke='#eee' strokeWidth={10}/>",
        "      <circle cx={60} cy={60} r={r} fill='none' stroke={fill} strokeWidth={10}",
        "        strokeDasharray={`${dash} ${circ}`} strokeLinecap='round'",
        "        style={{ transition: 'stroke-dasharray 0.8s ease', transform: 'rotate(-90deg)',",
        "          transformOrigin: '50% 50%' }}/>",
        "      <text x={60} y={65} textAnchor='middle' fontSize={22} fontWeight={700}",
        "        fill={fill}>{score}</text>",
        "    </svg>",
        "  );",
        "};",
      ]),

      gap(320),
      divider(),

      // ── 5. FASTAPI BACKEND ────────────────────────────────────────────────
      h("5. FastAPI Backend", HeadingLevel.HEADING_1),
      p("Deployed on Railway (or Render). Exposes three endpoints. Receives the telemetry bundle, orchestrates all analysis passes, writes to Supabase, and returns a single combined response object."),
      gap(),

      twoColTable([
        ["Endpoint", "Purpose"],
        ["GET /health", "Liveness probe for Railway deployment. Returns {status: ok, version}."],
        ["POST /analyze", "Main analysis endpoint. Accepts telemetry JSON + screenshot base64. Returns full verdict object including share_token."],
        ["GET /report/{token}", "Fetches a previously generated report by share token. Powers the public shareable page."],
        ["GET /domain/{domain}", "Returns crowd reputation for a domain. Used by the extension to show prior flags before running full analysis."],
        ["GET /graph/{domain}", "Returns phishing network edges for a domain for the D3 visualizer."],
      ]),

      gap(),

      h("5.1 scorer.py — Heuristic Pre-Score v2", HeadingLevel.HEADING_2),
      p("Extended from the original with additional weighted signals and reputation API inputs. Score is 0–100 (higher = safer). All deductions are capped to prevent over-penalization from a single signal."),
      gap(),

      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [4500, 1800, 3060],
        borders: { top: noBorder(), bottom: noBorder(), left: noBorder(), right: noBorder(), insideH: border(), insideV: border() },
        rows: [
          new TableRow({ children: [
            new TableCell({ shading: { fill: C.purple, type: ShadingType.CLEAR }, borders: borders(C.border), margins: cellMargins, width: { size: 4500, type: WidthType.DXA }, children: [new Paragraph({ children: [new TextRun({ text: "Signal", bold: true, color: C.white, size: 20 })], spacing: spacing(0,0) })] }),
            new TableCell({ shading: { fill: C.purple, type: ShadingType.CLEAR }, borders: borders(C.border), margins: cellMargins, width: { size: 1800, type: WidthType.DXA }, children: [new Paragraph({ children: [new TextRun({ text: "Deduction", bold: true, color: C.white, size: 20 })], spacing: spacing(0,0) })] }),
            new TableCell({ shading: { fill: C.purple, type: ShadingType.CLEAR }, borders: borders(C.border), margins: cellMargins, width: { size: 3060, type: WidthType.DXA }, children: [new Paragraph({ children: [new TextRun({ text: "Notes", bold: true, color: C.white, size: 20 })], spacing: spacing(0,0) })] }),
          ]}),
          ...[
            ["No HTTPS", "–30", "Immediate red flag"],
            ["VirusTotal: any malicious vendor flag", "–40", "Cap at 1 application per scan"],
            ["External form action (login form posts to diff domain)", "–35", "Strongest phishing signal"],
            ["Login form on HTTP page", "–20", "Credential harvesting risk"],
            ["No privacy policy link found", "–15", "Trust signal absent"],
            ["Phishing keyword density > 3 per page", "–25", "Urgency/threat language"],
            ["URLScan flagged in last 30 days", "–30", "Recent known-bad activity"],
            ["AbuseIPDB score > 50", "–20", "Malicious IP infrastructure"],
            ["Shortened URLs in links", "–20", "Up to 4 instances, –5 each"],
            ["No terms of service link", "–10", "Minor trust signal"],
            ["No contact page", "–5", "Minor trust signal"],
            ["Credit card field present", "–10", "Context-dependent risk"],
            ["Crowd flag rate > 20% of scans", "–15", "Community intelligence"],
          ].map(([signal, ded, notes], i) => new TableRow({ children: [
            new TableCell({ shading: { fill: i % 2 === 0 ? C.white : C.grayLight, type: ShadingType.CLEAR }, borders: borders(C.border), margins: cellMargins, width: { size: 4500, type: WidthType.DXA }, children: [new Paragraph({ children: [new TextRun({ text: signal, size: 20 })], spacing: spacing(0,0) })] }),
            new TableCell({ shading: { fill: i % 2 === 0 ? C.white : C.grayLight, type: ShadingType.CLEAR }, borders: borders(C.border), margins: cellMargins, width: { size: 1800, type: WidthType.DXA }, children: [new Paragraph({ children: [new TextRun({ text: ded, bold: true, color: C.red, size: 20 })], spacing: spacing(0,0) })] }),
            new TableCell({ shading: { fill: i % 2 === 0 ? C.white : C.grayLight, type: ShadingType.CLEAR }, borders: borders(C.border), margins: cellMargins, width: { size: 3060, type: WidthType.DXA }, children: [new Paragraph({ children: [new TextRun({ text: notes, color: C.gray, size: 20 })], spacing: spacing(0,0) })] }),
          ]})),
        ],
      }),

      gap(),

      h("5.2 vision.py — Gemini Vision Screenshot Analysis (NEW)", HeadingLevel.HEADING_2),
      callout(
        "DEMO MOMENT",
        "This is the single most impressive feature in the demo. Judges will watch Gemini describe specific visual deception on a phishing page — 'The login form mimics a PayPal interface but the domain does not match' — from a live screenshot captured seconds earlier.",
        C.amberLight,
        C.amber
      ),
      gap(),
      p("vision.py receives the base64 PNG from the request body, constructs a multimodal Gemini prompt, and returns structured visual observations."),
      gap(),

      codeBlock([
        "# backend/vision.py",
        "import google.generativeai as genai",
        "import base64",
        "",
        "VISION_PROMPT = '''",
        "You are a cybersecurity analyst specializing in visual phishing detection.",
        "Examine this webpage screenshot for visual deception techniques:",
        "- Brand impersonation (fake logos, misspelled brand names)",
        "- Misleading UI elements (fake security badges, false urgency banners)",
        "- Suspicious form design (login boxes on pages claiming to be elsewhere)",
        "- Layout anomalies that suggest a cloned or hastily constructed page",
        "",
        "Return ONLY a JSON object with this exact schema:",
        "{",
        '  "visual_verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS",',
        '  "confidence": 0.0-1.0,',
        '  "observations": ["string", ...],',
        '  "impersonated_brand": "string or null"',
        "}",
        "'''",
        "",
        "def analyze_screenshot(base64_png: str) -> dict:",
        "    model = genai.GenerativeModel('gemini-2.5-flash')",
        "    image_part = {",
        "        'mime_type': 'image/png',",
        "        'data': base64.b64decode(base64_png)",
        "    }",
        "    response = model.generate_content(",
        "        [VISION_PROMPT, image_part],",
        "        generation_config=genai.GenerationConfig(",
        "            response_mime_type='application/json'",
        "        )",
        "    )",
        "    return response.text  # guaranteed JSON",
      ]),

      gap(),

      h("5.3 prompts.py — Structured JSON Output Mode", HeadingLevel.HEADING_2),
      p("The original prompts.py returns freetext which requires fragile string parsing. The new version uses Gemini's response_mime_type + response_schema to return a guaranteed valid JSON object every time."),
      gap(),

      codeBlock([
        "# backend/prompts.py — Structured Gemini response",
        "RESPONSE_SCHEMA = {",
        '    "type": "object",',
        '    "properties": {',
        '        "verdict": {"type": "string", "enum": ["SAFE","SUSPICIOUS","DANGEROUS"]},',
        '        "confidence": {"type": "number"},',
        '        "risk_factors": {"type": "array", "items": {"type": "string"}},',
        '        "recommendations": {"type": "array", "items": {"type": "string"}},',
        '        "summary": {"type": "string"},',
        '        "safe_to_proceed": {"type": "boolean"}',
        "    }",
        "}",
        "",
        "def get_ai_verdict(telemetry: dict, pre_score: int, flagged: list) -> dict:",
        "    model = genai.GenerativeModel('gemini-2.5-flash')",
        "    prompt = build_prompt(telemetry, pre_score, flagged)",
        "    response = model.generate_content(",
        "        prompt,",
        "        generation_config=genai.GenerationConfig(",
        "            response_mime_type='application/json',",
        "            response_schema=RESPONSE_SCHEMA",
        "        )",
        "    )",
        "    return json.loads(response.text)  # always valid, no try/catch needed",
      ]),

      gap(),

      h("5.4 reputation.py — External Threat Intelligence (NEW)", HeadingLevel.HEADING_2),
      p("Queries three free-tier APIs in parallel using asyncio.gather(). Results are merged into pre-score inputs before Gemini is called."),
      gap(),

      twoColTable([
        ["API", "What it provides"],
        ["VirusTotal (free tier)", "90+ security vendor verdicts for the domain. Any malicious flag = –40 from pre-score."],
        ["URLScan.io (free)", "Prior scan history. Flags if the domain was reported malicious in last 30 days."],
        ["AbuseIPDB (free)", "IP reputation score. Server IP with score > 50 = –20 from pre-score."],
      ]),

      gap(),

      h("5.5 rate_limiter.py — Abuse Prevention (NEW)", HeadingLevel.HEADING_2),
      p("Uses slowapi with Redis backend (Upstash free tier) to apply a sliding window rate limit of 30 requests per IP per minute on POST /analyze. Prevents Gemini API cost runaway if the extension is exposed publicly."),
      gap(),

      codeBlock([
        "# backend/rate_limiter.py",
        "from slowapi import Limiter",
        "from slowapi.util import get_remote_address",
        "",
        'limiter = Limiter(key_func=get_remote_address, storage_uri="redis://...")',
        "",
        "# In app.py:",
        "@app.post('/analyze')",
        "@limiter.limit('30/minute')",
        "async def analyze(request: Request, body: TelemetryBody):",
        "    ...",
      ]),

      gap(320),
      divider(),

      // ── 6. SUPABASE INTELLIGENCE LAYER ────────────────────────────────────
      h("6. Supabase Intelligence Layer", HeadingLevel.HEADING_1),
      p("Supabase provides PostgreSQL, pgvector for semantic similarity search, Row Level Security for safe public reads, and Edge Functions for server-side aggregation logic. The free tier is sufficient for a hackathon deployment."),
      gap(),

      h("6.1 Database Schema", HeadingLevel.HEADING_2),
      gap(),
      codeBlock([
        "-- 001_init.sql",
        "",
        "-- Domain-level crowd reputation",
        "CREATE TABLE domain_reputation (",
        "  domain         TEXT PRIMARY KEY,",
        "  score          INT NOT NULL DEFAULT 50,",
        "  flags          JSONB,              -- { no_https, external_form, ... }",
        "  report_count   INT NOT NULL DEFAULT 0,",
        "  flag_count     INT NOT NULL DEFAULT 0,",
        "  first_seen     TIMESTAMPTZ DEFAULT NOW(),",
        "  last_seen      TIMESTAMPTZ DEFAULT NOW()",
        ");",
        "",
        "-- Individual scan records (one per user scan)",
        "CREATE TABLE scan_reports (",
        "  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),",
        "  share_token    UUID UNIQUE DEFAULT gen_random_uuid(),",
        "  domain         TEXT REFERENCES domain_reputation(domain),",
        "  telemetry      JSONB,",
        "  ai_verdict     JSONB,",
        "  vision_verdict JSONB,",
        "  pre_score      INT,",
        "  final_score    INT,",
        "  created_at     TIMESTAMPTZ DEFAULT NOW()",
        ");",
        "",
        "-- Phishing infrastructure graph edges",
        "CREATE TABLE phishing_network (",
        "  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),",
        "  domain_a       TEXT,",
        "  domain_b       TEXT,",
        "  edge_type      TEXT CHECK (edge_type IN",
        "                   ('shared_ip','shared_cert','shared_registrar')),",
        "  confidence     FLOAT,",
        "  UNIQUE(domain_a, domain_b, edge_type)",
        ");",
        "",
        "-- pgvector for semantic similarity between scan reports",
        "CREATE EXTENSION IF NOT EXISTS vector;",
        "ALTER TABLE scan_reports ADD COLUMN embedding vector(768);",
        "",
        "-- Public read RLS (no auth needed for hackathon demo)",
        "ALTER TABLE domain_reputation ENABLE ROW LEVEL SECURITY;",
        "ALTER TABLE scan_reports ENABLE ROW LEVEL SECURITY;",
        "CREATE POLICY 'public read' ON domain_reputation FOR SELECT USING (true);",
        "CREATE POLICY 'public read' ON scan_reports FOR SELECT USING (true);",
      ]),

      gap(),

      h("6.2 Edge Functions", HeadingLevel.HEADING_2),
      gap(),

      twoColTable([
        ["Edge Function", "Purpose"],
        ["aggregate_domain", "Called after every scan. Upserts domain_reputation with updated score, increments report_count and flag_count if the scan flagged issues."],
        ["embed_report", "Generates a text embedding of the scan summary and stores it in scan_reports.embedding using pgvector. Enables semantic similarity search to find related phishing sites."],
        ["build_network", "After each scan, checks if the scanned domain's IP, certificate fingerprint, or registrar matches any existing domain in scan_reports. Creates phishing_network edges where matches are found."],
      ]),

      gap(320),
      divider(),

      // ── 7. OUTPUT SURFACES ────────────────────────────────────────────────
      h("7. Output Surfaces", HeadingLevel.HEADING_1),

      h("7.1 Extension Popup", HeadingLevel.HEADING_2),
      p("The popup is the primary interaction surface. It loads in under 200ms because it first shows cached crowd data from domain_reputation (fast Supabase read) while the full Gemini analysis runs in the background. Layout:"),
      gap(),
      bullet("Header: domain name + HTTPS padlock or warning icon"),
      bullet("Hero: TrustRing SVG with animated score fill, verdict label, confidence percentage"),
      bullet("CrowdBadge: 'N users scanned this domain. M flagged it as unsafe.'"),
      bullet("Visual Insights panel: Gemini Vision observations (expandable)"),
      bullet("Risk accordion: Phishing / Privacy / Network / Trust — each collapsible"),
      bullet("Footer: Share Report button + 'Report this site' user flag button"),
      gap(),

      h("7.2 Shareable Public Report Page", HeadingLevel.HEADING_2),
      p("Every scan generates a unique public URL: https://sentinel-app.up.railway.app/r/{share_token}. This page:"),
      gap(),
      bullet("Renders a full-page breakdown of the scan: all scores, all AI verdict text, all visual observations"),
      bullet("Shows a social share card (Open Graph meta tags) so sharing on Twitter/LinkedIn shows a preview"),
      bullet("Includes a PDF download button (html2pdf.js client-side)"),
      bullet("Shows the phishing network graph inline if the domain has known connections"),
      gap(),
      callout(
        "DEMO TIP",
        "Hand judges this URL before the presentation. If they open it on their phone while you demo, it signals that you have a live deployed product, not a localhost prototype.",
        C.blueLight,
        C.blue
      ),

      gap(),

      h("7.3 Phishing Network Graph (D3)", HeadingLevel.HEADING_2),
      p("A force-directed graph rendered with D3.js that shows infrastructure connections between phishing domains. Nodes are domains, edges are typed (shared IP, certificate, registrar). Node size scales with report_count. Node color encodes danger level (red = DANGEROUS, amber = SUSPICIOUS, green = SAFE)."),
      gap(),
      p("This is the visually spectacular element for the judge demo. Seed the database with 10–15 known phishing domains from openphish.com before the presentation. The graph will show a connected cluster of malicious infrastructure — exactly the kind of threat intelligence output that looks like a real security product."),
      gap(),

      h("7.4 Admin Dashboard", HeadingLevel.HEADING_2),
      p("A single-page React dashboard at /dashboard (protected by a simple env-var password for demo purposes). Shows:"),
      gap(),
      bullet("Total scans today / this week"),
      bullet("Domains flagged in last 24 hours"),
      bullet("Live scan feed (Supabase realtime subscription)"),
      bullet("Top 10 most-scanned domains table"),
      bullet("World map of scan origins (if browser locale is captured)"),

      gap(320),
      divider(),

      // ── 8. FULL FILE STRUCTURE ────────────────────────────────────────────
      h("8. Complete File Structure", HeadingLevel.HEADING_1),
      gap(),
      codeBlock([
        "site-sentinel/",
        "├── extension/",
        "│   ├── manifest.json            # MV3, offscreen permission added",
        "│   ├── offscreen.html           # NEW: screenshot capture context",
        "│   ├── offscreen.js             # NEW: captureVisibleTab()",
        "│   ├── background.js            # Updated: triggers screenshot capture",
        "│   ├── content.js               # Updated: extended DOM signals",
        "│   └── popup/                   # NEW: React app",
        "│       ├── package.json",
        "│       ├── vite.config.js",
        "│       └── src/",
        "│           ├── App.jsx",
        "│           ├── api.js           # fetch() wrapper for backend calls",
        "│           └── components/",
        "│               ├── TrustRing.jsx",
        "│               ├── VerdictCard.jsx",
        "│               ├── CrowdBadge.jsx",
        "│               ├── RiskFactorList.jsx",
        "│               ├── ScreenshotInsights.jsx",
        "│               └── ShareButton.jsx",
        "│",
        "└── backend/",
        "    ├── app.py                   # FastAPI router, CORS, rate limiter",
        "    ├── scorer.py                # Heuristic pre-score v2",
        "    ├── prompts.py               # Structured Gemini text analysis",
        "    ├── vision.py                # NEW: Gemini Vision screenshot",
        "    ├── reputation.py            # NEW: VirusTotal + URLScan + AbuseIPDB",
        "    ├── report_gen.py            # NEW: Supabase write + share token",
        "    ├── rate_limiter.py          # NEW: slowapi Redis middleware",
        "    ├── models.py                # Pydantic request/response models",
        "    ├── Dockerfile               # NEW: Railway deployment",
        "    ├── requirements.txt         # Updated dependencies",
        "    ├── .env                     # GEMINI_API_KEY, SUPABASE_URL, VT_KEY",
        "    └── supabase/",
        "        └── migrations/",
        "            └── 001_init.sql     # All tables + RLS + pgvector",
      ]),

      gap(320),
      divider(),

      // ── 9. DEPLOYMENT ─────────────────────────────────────────────────────
      h("9. Deployment Guide", HeadingLevel.HEADING_1),

      h("9.1 Backend — Railway (30 minutes)", HeadingLevel.HEADING_2),
      numbered("Create a free account at railway.app"),
      numbered("New Project → Deploy from GitHub repo"),
      numbered("Add environment variables: GEMINI_API_KEY, SUPABASE_URL, SUPABASE_KEY, VT_API_KEY, URLSCAN_API_KEY, ABUSEIPDB_KEY"),
      numbered("Railway auto-detects the Dockerfile and deploys"),
      numbered("Copy the generated URL (e.g. site-sentinel.up.railway.app)"),
      numbered("Update extension/popup/src/api.js BASE_URL to this URL"),
      numbered("Rebuild the popup: cd popup && npm run build"),
      gap(),

      h("9.2 Supabase — Database (20 minutes)", HeadingLevel.HEADING_2),
      numbered("Create a free project at supabase.com"),
      numbered("Open SQL Editor, paste and run 001_init.sql"),
      numbered("Copy Project URL and anon key to backend .env"),
      numbered("Deploy the three Edge Functions from supabase/functions/"),
      gap(),

      h("9.3 Extension — Chrome (5 minutes)", HeadingLevel.HEADING_2),
      numbered("Run npm run build in the popup directory to generate dist/"),
      numbered("Open chrome://extensions → Enable Developer Mode"),
      numbered("Click Load Unpacked → select the extension/ directory"),
      numbered("Pin the extension to the toolbar"),
      gap(),

      h("9.4 Dockerfile", HeadingLevel.HEADING_2),
      codeBlock([
        "FROM python:3.12-slim",
        "WORKDIR /app",
        "COPY requirements.txt .",
        "RUN pip install --no-cache-dir -r requirements.txt",
        "COPY . .",
        "EXPOSE 8000",
        'CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]',
      ]),

      gap(320),
      divider(),

      // ── 10. TECH STACK ────────────────────────────────────────────────────
      h("10. Full Technology Stack", HeadingLevel.HEADING_1),
      gap(),

      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [2400, 3000, 3960],
        borders: { top: noBorder(), bottom: noBorder(), left: noBorder(), right: noBorder(), insideH: border(), insideV: border() },
        rows: [
          new TableRow({ children: [
            new TableCell({ shading: { fill: C.purple, type: ShadingType.CLEAR }, borders: borders(C.border), margins: cellMargins, width: { size: 2400, type: WidthType.DXA }, children: [new Paragraph({ children: [new TextRun({ text: "Layer", bold: true, color: C.white, size: 20 })], spacing: spacing(0,0) })] }),
            new TableCell({ shading: { fill: C.purple, type: ShadingType.CLEAR }, borders: borders(C.border), margins: cellMargins, width: { size: 3000, type: WidthType.DXA }, children: [new Paragraph({ children: [new TextRun({ text: "Component / Library", bold: true, color: C.white, size: 20 })], spacing: spacing(0,0) })] }),
            new TableCell({ shading: { fill: C.purple, type: ShadingType.CLEAR }, borders: borders(C.border), margins: cellMargins, width: { size: 3960, type: WidthType.DXA }, children: [new Paragraph({ children: [new TextRun({ text: "Notes", bold: true, color: C.white, size: 20 })], spacing: spacing(0,0) })] }),
          ]}),
          ...[
            ["Browser Extension", "Chrome MV3, Vanilla JS", "Offscreen Docs API for screenshot"],
            ["Popup UI", "React 18, Vite, Tailwind CSS", "Built into dist/, loaded by manifest"],
            ["AI — Text", "Gemini 2.5 Flash (JSON mode)", "Structured output, no string parsing"],
            ["AI — Vision", "Gemini 2.5 Flash (multimodal)", "Screenshot + text prompt"],
            ["Backend Framework", "FastAPI + Python 3.12", "Async, type-safe, auto OpenAPI docs"],
            ["ASGI Server", "Uvicorn", "Prod: gunicorn -k uvicorn.workers"],
            ["Validation", "Pydantic v2", "Request/response models"],
            ["Rate Limiting", "slowapi + Upstash Redis", "Sliding window, per-IP"],
            ["Database", "Supabase (PostgreSQL 15)", "pgvector extension enabled"],
            ["Semantic Search", "pgvector + Gemini Embeddings", "768-dimension vectors"],
            ["File Storage", "Supabase Storage", "Screenshot archive (optional)"],
            ["Realtime", "Supabase Realtime", "Live scan feed on dashboard"],
            ["Reputation APIs", "VirusTotal, URLScan, AbuseIPDB", "All free tier, parallel fetch"],
            ["Frontend Graph", "D3.js v7 (force-directed)", "Phishing network visualizer"],
            ["Deployment", "Railway (backend), Supabase (DB)", "Both free tier, both public URLs"],
            ["PDF Export", "html2pdf.js", "Client-side, shareable report"],
          ].map(([layer, comp, notes], i) => new TableRow({ children: [
            new TableCell({ shading: { fill: i % 2 === 0 ? C.white : C.grayLight, type: ShadingType.CLEAR }, borders: borders(C.border), margins: cellMargins, width: { size: 2400, type: WidthType.DXA }, children: [new Paragraph({ children: [new TextRun({ text: layer, bold: true, size: 20 })], spacing: spacing(0,0) })] }),
            new TableCell({ shading: { fill: i % 2 === 0 ? C.white : C.grayLight, type: ShadingType.CLEAR }, borders: borders(C.border), margins: cellMargins, width: { size: 3000, type: WidthType.DXA }, children: [new Paragraph({ children: [new TextRun({ text: comp, font: "Courier New", size: 20, color: C.purple })], spacing: spacing(0,0) })] }),
            new TableCell({ shading: { fill: i % 2 === 0 ? C.white : C.grayLight, type: ShadingType.CLEAR }, borders: borders(C.border), margins: cellMargins, width: { size: 3960, type: WidthType.DXA }, children: [new Paragraph({ children: [new TextRun({ text: notes, color: C.gray, size: 20 })], spacing: spacing(0,0) })] }),
          ]})),
        ],
      }),

      gap(320),
      divider(),

      // ── 11. PRIORITY BUILD ORDER ──────────────────────────────────────────
      h("11. Priority Build Order", HeadingLevel.HEADING_1),
      p("If time is limited, build in this exact order. Each item is a complete deliverable that adds standalone value to the demo."),
      gap(),

      priorityTable([
        ["Priority", "Feature", "Time", "Judge Impact"],
        ["P0", "Deploy backend to Railway with Dockerfile", "30 min", "Critical — no live demo without this"],
        ["P0", "Structured Gemini JSON output (prompts.py)", "1 hr", "Eliminates fragile parsing, more reliable demo"],
        ["P1", "Supabase schema + scan_reports + share token", "2 hr", "Enables shareable URL — biggest credibility signal"],
        ["P1", "TrustRing React popup UI + VerdictCard", "2 hr", "Visual polish judges remember"],
        ["P2", "offscreen.js screenshot + vision.py Gemini Vision", "3 hr", "The demo moment — no other team has this"],
        ["P2", "reputation.py (VirusTotal + URLScan)", "2 hr", "Multi-source intel, stronger scores"],
        ["P3", "domain_reputation crowd aggregation", "2 hr", "The 'N users flagged this' badge"],
        ["P3", "D3 phishing network graph", "4 hr", "Visually spectacular, high wow factor"],
        ["P4", "Admin dashboard with live feed", "3 hr", "Good for extended demo, not essential"],
      ]),

      gap(320),
      divider(),

      // ── 12. DEMO SCRIPT ───────────────────────────────────────────────────
      h("12. The 60-Second Judge Demo Script", HeadingLevel.HEADING_1),
      p("Follow this script exactly. Every step is designed to produce a visible reaction from judges."),
      gap(),

      callout(
        "BEFORE THE PRESENTATION",
        "Seed your Supabase domain_reputation with 15–20 known phishing domains from openphish.com or phishing.army. This ensures the crowd badge shows real numbers and the D3 graph shows a connected network. Do this the night before.",
        C.coralLight,
        C.coral
      ),

      gap(),

      numbered("Navigate to a known phishing demo site. Use a sample from openphish.com or use checkphishing.org. Say: 'Here is a live phishing site.'"),
      numbered("Click the Site Sentinel extension icon. Say: 'I'll run a real-time analysis.' The TrustRing animates to red. Pause here. Let judges see it."),
      numbered("Point to the CrowdBadge. Say: 'Our system has already seen this domain — 31 other users scanned it, 28 flagged it as dangerous.'"),
      numbered("Expand the Visual Insights panel. Read out one Gemini Vision observation verbatim. Say: 'Our AI analyzed the actual screenshot and identified this specific visual deception.'"),
      numbered("Click Share Report. Copy the URL. Open it in a second browser window (or on your phone). Say: 'Every analysis generates a permanent shareable report at a public URL.'"),
      numbered("Navigate to /graph. The D3 network appears. Say: 'This domain shares infrastructure with three other phishing sites — same IP, same certificate authority. This is threat intelligence, not just a safety score.'"),
      numbered("End with: 'Site Sentinel AI is deployed, live, and has already protected real users from real threats.'"),

      gap(320),
      divider(),

      // ── 13. API KEY SETUP ─────────────────────────────────────────────────
      h("13. Environment Variables & API Key Setup", HeadingLevel.HEADING_1),
      gap(),

      twoColTable([
        ["Variable", "Where to get it"],
        ["GEMINI_API_KEY", "aistudio.google.com/app/apikey — free, no credit card"],
        ["SUPABASE_URL", "Supabase project Settings → API → Project URL"],
        ["SUPABASE_KEY", "Supabase project Settings → API → anon public key"],
        ["VT_API_KEY", "virustotal.com → Sign up free → API Key in profile"],
        ["URLSCAN_API_KEY", "urlscan.io → Sign up free → API Key in settings"],
        ["ABUSEIPDB_KEY", "abuseipdb.com → Sign up free → API tab"],
        ["REDIS_URL", "upstash.com → Create Redis database → Copy REST URL"],
        ["BACKEND_URL", "Set in extension/popup/src/api.js after Railway deploy"],
      ]),

      gap(320),
      divider(),

      // ── 14. SECURITY NOTES ────────────────────────────────────────────────
      h("14. Security Notes", HeadingLevel.HEADING_1),
      bullet("All API keys are stored in Railway environment variables, never in the codebase. The .env file is in .gitignore."),
      bullet("CORS is locked to the Chrome extension origin in production (chrome-extension://{your-id}). Not allow-all as in the original."),
      bullet("Rate limiting prevents Gemini API cost abuse. Set Gemini API quota limits in Google Cloud Console as a secondary guard."),
      bullet("Supabase RLS policies allow public SELECT on domain_reputation and scan_reports (by share_token only). INSERT and UPDATE are backend-only via the service role key."),
      bullet("The share token is a UUID v4 generated by PostgreSQL — 122 bits of entropy, effectively unguessable."),
      bullet("Screenshots are never stored by default. They are processed in memory and discarded after Gemini Vision returns. Optional archival to Supabase Storage can be added post-hackathon."),

      gap(320),

      // ── CLOSING ───────────────────────────────────────────────────────────
      new Paragraph({
        alignment: AlignmentType.CENTER,
        border: { top: { style: BorderStyle.SINGLE, size: 4, color: C.purple } },
        children: [],
        spacing: spacing(480, 160),
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "Site Sentinel AI  ·  Global Tech Hackathon 2026", bold: true, color: C.purple, size: 22 })],
        spacing: spacing(0, 80),
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "Built by Secyra", color: C.gray, size: 20 })],
        spacing: spacing(0, 0),
      }),
    ],
  }],
});

// ── Output ────────────────────────────────────────────────────────────────────
const outputPath = path.join(__dirname, 'SiteSentinel_Architecture.docx');

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(outputPath, buffer);
  console.log(`Document generated: ${outputPath}`);
});
