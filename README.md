# TrustChecker - AI-Powered Scam Detection Platform

TrustChecker is a premium, Vercel-inspired cybersecurity SaaS platform designed to help users identify online fraud, phishing attempts, fake job offers, scam eCommerce storefronts, and telemarketing numbers.

> **Slogan:** "Check before you trust."

---

## 🚀 Key Features

1. **Website Scam Checker:** Audit domains for registration age, SSL indicators, and brand-impersonation typo-squatting risks.
2. **Job Offer Auditor:** Analyze recruitment conversations, Telegram/WhatsApp requests, and equipment-purchasing cashier check scams.
3. **Phishing Email Classifier:** Scan suspicious email text for urgency flags, credentials harvesting links, and lottery baits.
4. **SMS / Text Inspector:** Identify package delivery spoofing (fake USPS/FedEx alerts) and bank account lock baits.
5. **Phone Reputation Lookup:** Search Caller IDs against robocaller logs and telemarketer directories.
6. **eCommerce Shop Auditor:** Evaluate suspicious discount shops (.shop/.store) and checkout indicators.
7. **Live Threat Feed:** Crowdsourced database logging realtime scam reports flagged by the community.

---

## 🛠️ Technology Stack & Styling

- **Core:** [AstroJS](https://astro.build/) (v6.4.6)
- **Styling:** [Tailwind CSS v4](https://tailwindcss.com/) (configured via PostCSS for maximum Vite environment compatibility)
- **Design Language:** Stark Vercel-like duet (canvas white, body gray, ink black CTAs) paired with subtle stacked shadows, monospace captions, and an organic multi-color mesh gradient blur background.
- **Fonts:** `Inter` (narrative geometric sans) and `JetBrains Mono` (technical layout captions).

---

## 📁 Project Structure

```text
/
├── public/                # Static assets (Favicons, web manifests)
├── src/
│   ├── components/        # Interactive Astro layout primitives
│   │   ├── AnalysisCard.astro        # Cyber forensics scan results presenter
│   │   ├── CommunityReport.astro     # Crowdsourced scam feed & submission form
│   │   ├── Footer.astro              # Clean Vercel-styled grid footer
│   │   ├── HistoryLog.astro          # LocalStorage search tracker
│   │   ├── InteractiveChecker.astro  # Core tabbed search panel & terminal simulator
│   │   ├── Navbar.astro              # Responsive header and navigation
│   │   └── TrustScoreDial.astro      # SVG radial risk-level meter
│   ├── layouts/
│   │   └── Layout.astro              # SEO-optimized viewport structure
│   ├── pages/             # Route templates and landing endpoints
│   │   ├── index.astro               # Landing dashboard index
│   │   ├── fake-job-offer-checker.astro
│   │   ├── is-this-website-legit.astro
│   │   ├── online-store-checker.astro
│   │   ├── phishing-email-checker.astro
│   │   ├── phone-number-scam-checker.astro
│   │   ├── scam-detector.astro
│   │   ├── sms-scam-checker.astro
│   │   └── website-scam-checker.astro
│   ├── styles/
│   │   └── global.css                # Tailwind imports and Vercel theme variables
│   └── utils/
│       └── scanEngine.ts             # Custom regex-heuristics threat analysis algorithm
├── astro.config.mjs       # Main configuration
├── postcss.config.mjs     # PostCSS configuration for Tailwind v4
└── package.json           # Dependencies and scripts
```

---

## 🧞 Dev Commands

All commands are run from the project root directory:

| Command | Action |
| :--- | :--- |
| `npm install` | Installs project dependencies |
| `npm run dev` | Boots up the local hot-reloading dev server at `http://localhost:4321` |
| `npm run build` | Compiles the optimized static production bundle in `dist/` |
| `npm run preview` | Runs a preview server for local bundle inspection |
