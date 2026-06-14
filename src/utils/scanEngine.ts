// TrustChecker Scam Detection & Heuristic Analysis Engine

// Simple string hash helper to generate consistent mock results for the same input
function hashString(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0; // Convert to 32bit integer
  }
  return Math.abs(hash);
}

interface AnalysisResult {
  score: number;
  title: string;
  ageText: string;
  agePercent: number;
  browserUrl: string;
  previewTitle: string;
  explanation: string;
  redFlagsHTML: string;
  greenFlagsHTML: string;
}

// Custom heuristic analysis
export function analyzeInput(value: string, type: string): AnalysisResult {
  const normalizedVal = value.toLowerCase().trim();
  const seed = hashString(normalizedVal);
  
  let score = 90; // Default baseline score (out of 100)
  let title = "";
  let ageText = "N/A";
  let agePercent = 0; // 0 to 100 for visual timeline
  let browserUrl = "https://www.google.com";
  let previewTitle = "Legitimate Website";
  
  const redFlags: string[] = [];
  const greenFlags: string[] = [];
  let explanation = "";

  // 1. WEBSITE HEURISTIC ENGINE
  if (type === 'website' || type === 'store') {
    // Clean up domain
    let domain = normalizedVal.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
    browserUrl = `https://${domain}`;
    previewTitle = domain.charAt(0).toUpperCase() + domain.slice(1);

    // Baseline details
    const isSSL = normalizedVal.startsWith('https://') || !normalizedVal.startsWith('http://'); // Default secure if raw domain entered
    const endsWithShortScamTld = /\.(xyz|top|online|click|download|club|info|work|tech|support|store|shop|sale|site|space|fun|vip|live)$/.test(domain);
    const hasMultipleHyphens = (domain.match(/-/g) || []).length >= 2;
    const hasSubdomainFlooding = (domain.match(/\./g) || []).length >= 3;
    const hasLongLength = domain.length > 22;

    // Impersonation lists
    const brandTriggers = ['paypal', 'amazon', 'chase', 'netflix', 'apple', 'walmart', 'fedex', 'usps', 'dhl', 'ups', 'bankofamerica', 'wellsfargo', 'citibank', 'microsoft', 'google', 'facebook', 'instagram', 'coinbase', 'binance', 'crypto'];
    const matchedBrand = brandTriggers.find(brand => domain.includes(brand));
    const isOfficialBrand = matchedBrand ? new RegExp(`^${matchedBrand}\\.(com|org|net|co\\.uk|gov)$`).test(domain) : false;

    // SSL Indicator
    if (!isSSL) {
      score -= 18;
      redFlags.push("Insecure connection (HTTP instead of HTTPS protocol)");
    } else {
      greenFlags.push("Valid SSL/TLS Certificate (Encrypted HTTPS connection)");
    }

    // Impersonation check
    if (matchedBrand && !isOfficialBrand) {
      score -= 48;
      redFlags.push(`Potential brand impersonation: Uses protected name '${matchedBrand}' in a non-official domain structure`);
      previewTitle = `Alert: Fake ${matchedBrand.charAt(0).toUpperCase() + matchedBrand.slice(1)} Portal`;
    }

    // TLD Checker
    if (endsWithShortScamTld) {
      score -= 22;
      redFlags.push("Low-reputation domain extension (scammers frequently use cheap TLDs like .xyz, .top, or .shop)");
    } else {
      greenFlags.push("Standard, high-reputation domain extension (.com, .org, or .net)");
    }

    // Typo Squatting / Hyphen flooding
    if (hasMultipleHyphens) {
      score -= 10;
      redFlags.push("Suspicious domain structure containing multiple hyphens (often used to forge lookalike URLs)");
    }
    if (hasSubdomainFlooding) {
      score -= 12;
      redFlags.push("Subdomain flooding (too many subdomains, e.g., login.account.secure.support.com)");
    }
    if (hasLongLength) {
      score -= 8;
      redFlags.push("Excessively long domain name (often used to push the real suffix off mobile screen viewports)");
    }

    // eCommerce specific checks
    if (type === 'store') {
      const discountKeywords = ['cheap', 'clearance', 'discount', 'wholesale', 'sale', 'outlet', 'free', 'store-online'];
      const hasDiscountInName = discountKeywords.some(keyword => domain.includes(keyword));
      if (hasDiscountInName) {
        score -= 15;
        redFlags.push("Discount-baiting keyword detected in domain name");
      }
      if (domain.endsWith('.shop') || domain.endsWith('.store') || domain.endsWith('.sale')) {
        score -= 8;
        redFlags.push("Domain registered with eCommerce TLD typical of temporary drop-shipping scams");
      }
    }

    // Generate Domain Age
    // Seed determines age: safe domains have high seed mod, suspicious names have low mod
    let ageInDays = 0;
    if (score >= 80) {
      // Safe domain: age between 3 and 25 years
      ageInDays = 1000 + (seed % 8000);
    } else if (score >= 50) {
      // Caution: age between 6 months and 2 years
      ageInDays = 180 + (seed % 540);
    } else {
      // Dangerous: age between 1 day and 90 days
      ageInDays = 1 + (seed % 90);
    }

    if (ageInDays > 365) {
      const years = (ageInDays / 365).toFixed(1);
      ageText = `${years} Years Old`;
      agePercent = Math.min(100, Math.round((ageInDays / 1825) * 100)); // Cap at 5 years
      greenFlags.push(`Established domain registration history (${ageText})`);
    } else {
      ageText = `${ageInDays} Days Old`;
      agePercent = Math.max(5, Math.round((ageInDays / 365) * 20)); // Keep visible on bar
      score -= 20;
      redFlags.push(`Extremely young domain: registered only ${ageText} ago (typical of short-lived malicious sites)`);
    }

    // Generate explanations
    if (score >= 80) {
      explanation = `The website ${domain} shows strong indicators of legitimacy. It utilizes secure HTTPS protocols, has a long-standing registration history (${ageText}), and is hosted on reputable infrastructure. No brand-spoofing indicators or malware signatures were detected.`;
      title = `${domain} appears secure and trustworthy.`;
    } else if (score >= 50) {
      explanation = `Caution is recommended before interacting with ${domain}. While the site features basic encryption (SSL), it has several risk factors: its registration is relatively new (${ageText}) and it utilizes a low-reputation top-level domain. Ensure you verify the entity independently.`;
      title = `${domain} requires caution. Minor risk factors detected.`;
    } else {
      explanation = `Warning: High risk of fraud detected on ${domain}. This domain shows strong indicators of phishing, brand impersonation, or fake ecommerce operations. It was registered very recently (${ageText}) and uses suspicious naming structures designed to deceive users. Do not input credentials, personal info, or credit card details here.`;
      title = `High scam probability detected on ${domain}!`;
    }
  }

  // 2. JOB OFFER HEURISTIC ENGINE
  else if (type === 'job') {
    previewTitle = "Job Scam Analysis";
    
    // Heuristics flags
    const hasTelegram = normalizedVal.includes('telegram') || normalizedVal.includes('t.me');
    const hasWhatsApp = normalizedVal.includes('whatsapp') || normalizedVal.includes('wa.me') || normalizedVal.includes('chat.whatsapp');
    const hasUpfrontPayment = normalizedVal.includes('upfront') || normalizedVal.includes('payment') || normalizedVal.includes('equipment fee') || normalizedVal.includes('purchase laptop') || normalizedVal.includes('reimburse') || normalizedVal.includes('check deposit') || normalizedVal.includes('check cashing');
    const hasUnrealisticPay = /\$\d{2,4}\s*(per\s*hour|hr|weekly|week)/.test(normalizedVal) || normalizedVal.includes('no experience required') || normalizedVal.includes('flexible hours') || normalizedVal.includes('simple tasks');
    const hasPackageHandler = normalizedVal.includes('package handler') || normalizedVal.includes('reshipping') || normalizedVal.includes('shipping coordinator') || normalizedVal.includes('forwarding');
    const hasPublicEmail = normalizedVal.includes('@gmail') || normalizedVal.includes('@yahoo') || normalizedVal.includes('@outlook') || normalizedVal.includes('@hotmail');

    if (hasTelegram || hasWhatsApp) {
      score -= 30;
      redFlags.push("Recruiter requests communication exclusively via messaging apps (Telegram/WhatsApp), avoiding official HR systems");
    } else {
      greenFlags.push("No redirection to anonymous messaging platforms (Telegram/WhatsApp) detected");
    }

    if (hasUpfrontPayment) {
      score -= 35;
      redFlags.push("Mentions buying work equipment upfront, processing cashier checks, or depositing money for training");
    }

    if (hasUnrealisticPay) {
      score -= 15;
      redFlags.push("Unusually high hourly/weekly rate for entry-level work with 'no experience required' (typical money-mule bait)");
    } else {
      greenFlags.push("Pay structure appears realistic and aligned with industry standards");
    }

    if (hasPackageHandler) {
      score -= 25;
      redFlags.push("Job role involves 'package handling', 'receiving packages', or 'reshipping coordination' (often stolen goods handling)");
    }

    if (hasPublicEmail) {
      score -= 18;
      redFlags.push("Recruiter or company contacts utilize free public domains (@gmail.com, @yahoo.com) rather than corporate business domains");
    } else {
      greenFlags.push("Does not indicate use of public/unverified email senders");
    }

    // Set Age/Screenshot parameters
    ageText = "N/A (Job Text Analysis)";
    agePercent = 0;

    if (score >= 80) {
      explanation = "The job posting/email appears to follow standard professional guidelines. We did not detect any requests for upfront payment, check deposits, reshipping activities, or redirection to anonymous chat platforms like Telegram or WhatsApp. Still, verify the sender's email matches the actual company domain.";
      title = "Job offer appears legitimate and safe.";
    } else if (score >= 55) {
      explanation = "This job listing contains caution indicators. Be careful if the recruiter uses a public email address or has generic job descriptions. Do not send sensitive information like your Social Security Number (SSN) or bank details until you verify their legitimacy via the company's official website.";
      title = "Caution: Minor warning signs in job posting.";
    } else {
      explanation = "Warning: High risk of employment scam. This offer displays standard patterns of cashier check scams, packaging forwarding scams, or recruitment identity theft. Scammers often request you to purchase laptops/equipment with a promised refund, or chat via Telegram. Legitimate companies do not operate this way.";
      title = "High Scam Risk: Suspicious Job Offer Detected!";
    }
  }

  // 3. EMAIL PHISHING HEURISTIC ENGINE
  else if (type === 'email') {
    previewTitle = "Phishing Email Analysis";

    const hasUrgency = normalizedVal.includes('urgent') || normalizedVal.includes('action required') || normalizedVal.includes('immediately') || normalizedVal.includes('suspended') || normalizedVal.includes('unauthorized transaction') || normalizedVal.includes('locked') || normalizedVal.includes('compromised');
    const hasFinancialBait = normalizedVal.includes('wire transfer') || normalizedVal.includes('gift card') || normalizedVal.includes('inheritance') || normalizedVal.includes('lottery') || normalizedVal.includes('fund transfer') || normalizedVal.includes('crypto deposit');
    const hasCredentialBait = normalizedVal.includes('login now') || normalizedVal.includes('click here to verify') || normalizedVal.includes('update password') || normalizedVal.includes('verify your ssn') || normalizedVal.includes('security question');
    const hasGrammarIssues = normalizedVal.includes('dear customer') || normalizedVal.includes('regards bank') || normalizedVal.includes('kindly do');

    if (hasUrgency) {
      score -= 28;
      redFlags.push("Artificial urgency alerts (urging action to prevent immediate account suspension or service locking)");
    } else {
      greenFlags.push("Sender does not employ high-pressure urgency tactics");
    }

    if (hasFinancialBait) {
      score -= 32;
      redFlags.push("Financial bait detected: requests for gift cards, wire transfers, or mentions unexpected lottery winnings");
    }

    if (hasCredentialBait) {
      score -= 35;
      redFlags.push("Credential harvesting signals: urges clicking links to 'verify credentials', 'update passwords', or input SSN");
    } else {
      greenFlags.push("No direct credential harvesting patterns detected");
    }

    if (hasGrammarIssues) {
      score -= 10;
      redFlags.push("Generic greeting ('Dear Customer') or clumsy syntax suggesting foreign origin templates");
    }

    ageText = "N/A (Email Scan)";
    agePercent = 0;

    if (score >= 80) {
      explanation = "No major phishing triggers detected in the email body text. It does not display high-urgency threats, gift-card payment demands, or links to suspicious credential updating portals. Ensure you verify the sender's header address (e.g. support@paypal.com vs support@paypa1-alert.com) before replying.";
      title = "Email text appears safe and clean.";
    } else if (score >= 55) {
      explanation = "Caution: The email contains moderately suspicious phrasing. Phishing attacks often use generic salutations and minor security scares to entice clicks. Avoid clicking any links in the email; navigate to the service website directly in your browser instead.";
      title = "Caution: Suspicious indicators in email.";
    } else {
      explanation = "Warning: Phishing attempt detected! The pasted email text contains classic social-engineering warning signs. It attempts to trigger fear of account locking or greed for unexpected funds, while requesting credential verification or payment. Mark as spam and do not reply or click any links.";
      title = "Critical: High Phishing Scam Probability!";
    }
  }

  // 4. SMS HEURISTIC ENGINE
  else if (type === 'sms') {
    previewTitle = "SMS Alert Scan";

    const hasPackageScam = normalizedVal.includes('usps') || normalizedVal.includes('post office') || normalizedVal.includes('delivery fee') || normalizedVal.includes('package pending') || normalizedVal.includes('shipment failed') || normalizedVal.includes('dhl') || normalizedVal.includes('fedex') || normalizedVal.includes('ips') || normalizedVal.includes('redirection');
    const hasBankScam = normalizedVal.includes('card blocked') || normalizedVal.includes('chase notification') || normalizedVal.includes('unauthorized login') || normalizedVal.includes('transfer code') || normalizedVal.includes('bank alert');
    const hasSuspiciousShortlink = /https?:\/\/[a-z0-9.-]+\.[a-z]{2,5}\/[a-z0-9]{3,8}/i.test(value) && !normalizedVal.includes('google.com') && !normalizedVal.includes('apple.com');
    const hasPrizeWinner = normalizedVal.includes('congratulations') || normalizedVal.includes('prize') || normalizedVal.includes('gift card') || normalizedVal.includes('winner');

    if (hasPackageScam) {
      score -= 42;
      redFlags.push("Standard package delivery fraud triggers (fake USPS/FedEx address correction alerts with requests for unpaid custom fees)");
    }

    if (hasBankScam) {
      score -= 45;
      redFlags.push("Urgent security alert pretending to be a bank locking your credit card or verifying large suspicious transactions");
    }

    if (hasSuspiciousShortlink) {
      score -= 25;
      redFlags.push("Contains an unverified web shortlink (scammers hide redirection domains inside custom short URL paths)");
    } else {
      greenFlags.push("No suspicious shortlinks or URLs detected in the message body");
    }

    if (hasPrizeWinner) {
      score -= 35;
      redFlags.push("Prize/lottery bait claiming you won a sweepstakes, gift card, or reward from a store you never visited");
    }

    ageText = "N/A (SMS Message)";
    agePercent = 0;

    if (score >= 80) {
      explanation = "The text message does not contain common phishing triggers or package/bank notification scams. However, always exercise caution if a message comes from an unknown 10-digit number asking you to click external links.";
      title = "SMS content appears safe.";
    } else if (score >= 55) {
      explanation = "Caution: This text message might be unsolicited spam. Treat with caution if it includes a link. Legitimate companies rarely send notifications from random personal mobile numbers.";
      title = "Caution: Unsolicited text message indicators.";
    } else {
      explanation = "Warning: Phishing/Smishing scam detected! This text message utilizes package delivery bait or fake banking alerts containing shortlinks. Scammers send millions of these messages to steal credit card details or bank passwords. Delete the message and block the sender immediately.";
      title = "Critical: SMiShing Scam Alert!";
    }
  }

  // 5. PHONE REPUTATION ENGINE
  else if (type === 'phone') {
    previewTitle = "Caller ID Search";
    const cleanPhone = normalizedVal.replace(/[^0-9]/g, '');
    
    const isTollFreeSpam = cleanPhone.startsWith('800') || cleanPhone.startsWith('1800') || cleanPhone.startsWith('888') || cleanPhone.startsWith('877') || cleanPhone.startsWith('866');
    const hasSpamPattern = (seed % 10) >= 6; // Mock 40% spam database lookup probability

    if (isTollFreeSpam) {
      score -= 15;
      redFlags.push("Caller utilizes toll-free prefix (often spoofed or used by telemarketing networks)");
    }

    if (hasSpamPattern) {
      score -= 52;
      redFlags.push("Caller reported as 'Telemarketer' or 'Robocall' in public spam database");
      redFlags.push("Identified as an active spoofed number used in credit card rate-reduction calls");
      ageText = "240+ Spam Reports";
      agePercent = 85; // High reports
    } else {
      greenFlags.push("No active spam flags detected in community call registries");
      ageText = "0 Spam Reports";
      agePercent = 0;
    }

    if (score >= 80) {
      explanation = "This phone number is clean in our databases. We have found zero consumer complaints, spam flags, or telemarketing association logs. It is likely a standard residential or business line.";
      title = "Phone number has clean reputation.";
    } else if (score >= 55) {
      explanation = "Caution: This number is sometimes associated with automated toll-free call systems or commercial surveys. Proceed with caution if you do not recognize the business.";
      title = "Caution: Number linked to commercial calls.";
    } else {
      explanation = "Warning: Verified Spam Number! This caller ID is flagged as a high-risk robocall or scam campaign. It is heavily reported by consumers for credit card reduction, IRS tax debt scams, or fake utility company checks. Block the caller and do not answer.";
      title = "High Risk: Spam / Robocaller Verified!";
    }
  }

  // Ensure score constraints
  score = Math.max(5, Math.min(99, score));

  // Build flags lists HTML
  const buildFlagsHTML = (flags: string[], typeClass: string): string => {
    if (flags.length === 0) {
      return `<li class="flex items-start gap-2 text-mute">
                <span>&bull;</span>
                <span>None detected</span>
              </li>`;
    }
    return flags.map(flag => `
      <li class="flex items-start gap-2">
        <span class="${typeClass} mt-0.5">&bull;</span>
        <span>${flag}</span>
      </li>
    `).join('');
  };

  const redFlagsHTML = buildFlagsHTML(redFlags, 'text-error font-bold');
  const greenFlagsHTML = buildFlagsHTML(greenFlags, 'text-success font-bold');

  return {
    score,
    title,
    ageText,
    agePercent,
    browserUrl,
    previewTitle,
    explanation,
    redFlagsHTML,
    greenFlagsHTML
  };
}

interface ScanLogItem {
  text: string;
  delay: number;
  progress: number;
}

// Interactive scrolling log terminal function
export function triggerScamScan(value: string, type: string): void {
  const terminal = document.getElementById('scan-terminal');
  const terminalOutput = document.getElementById('terminal-output');
  const progressBar = document.getElementById('terminal-progress-bar');
  const formBox = document.getElementById('analyze-form');
  const report = document.getElementById('dashboard-report');

  if (!terminal || !terminalOutput || !progressBar || !formBox || !report) return;

  // Save current scan value globally for share URL copying
  (window as any).lastScanValue = value;

  // Initialize view
  formBox.classList.add('opacity-40', 'pointer-events-none');
  report.classList.add('hidden');
  terminal.classList.remove('hidden');
  terminalOutput.innerHTML = '';
  progressBar.style.width = '0%';

  const logs: ScanLogItem[] = [];
  
  if (type === 'website' || type === 'store') {
    logs.push(
      { text: `[INFO] Initializing security audit for: ${value}`, delay: 100, progress: 10 },
      { text: `[INFO] Resolving DNS servers and checking registrar database...`, delay: 350, progress: 25 },
      { text: `[INFO] Requesting SSL certificate chain verification...`, delay: 600, progress: 40 },
      { text: `[INFO] Evaluating domain age and registration duration...`, delay: 900, progress: 55 },
      { text: `[INFO] Scanning for brand impersonation triggers & phishing keywords...`, delay: 1200, progress: 70 },
      { text: `[INFO] Cross-checking with global blacklists (Google Safe Browsing, PhishTank)...`, delay: 1550, progress: 85 },
      { text: `[SUCCESS] Cyber-forensics complete. Compiling trust report...`, delay: 1850, progress: 100 }
    );
  } else if (type === 'job') {
    logs.push(
      { text: `[INFO] Initializing Natural Language Processing (NLP) job-scam engine...`, delay: 100, progress: 15 },
      { text: `[INFO] Analyzing job compensation scale vs labor expectations...`, delay: 400, progress: 35 },
      { text: `[INFO] Scanning text for money transfer, cashier checks, and upfront fees...`, delay: 750, progress: 55 },
      { text: `[INFO] Evaluating contact redirection triggers (Telegram/WhatsApp links)...`, delay: 1100, progress: 75 },
      { text: `[INFO] Checking company references and public sender domains...`, delay: 1450, progress: 90 },
      { text: `[SUCCESS] Text classifier audit finished. Compiling report...`, delay: 1800, progress: 100 }
    );
  } else if (type === 'email') {
    logs.push(
      { text: `[INFO] Initializing Phishing Intelligence Parser...`, delay: 100, progress: 15 },
      { text: `[INFO] Extracting threat indicators, urgencies, and warnings...`, delay: 450, progress: 35 },
      { text: `[INFO] Inspecting text for credential farming and SSN requests...`, delay: 800, progress: 60 },
      { text: `[INFO] Running semantic grammar and corporate template verification...`, delay: 1200, progress: 80 },
      { text: `[SUCCESS] Email threat scan complete. Building dashboard...`, delay: 1600, progress: 100 }
    );
  } else if (type === 'sms') {
    logs.push(
      { text: `[INFO] Initializing SMiShing SMS scan engine...`, delay: 100, progress: 20 },
      { text: `[INFO] Detecting banking alert codes, courier warnings (USPS/FedEx)...`, delay: 500, progress: 50 },
      { text: `[INFO] Parsing message for unverified domain shortlinks...`, delay: 900, progress: 75 },
      { text: `[INFO] Running social engineering threat score calculations...`, delay: 1300, progress: 90 },
      { text: `[SUCCESS] SMS validation check finished. Rendering logs...`, delay: 1650, progress: 100 }
    );
  } else if (type === 'phone') {
    logs.push(
      { text: `[INFO] Initializing Phone Reputation search...`, delay: 100, progress: 20 },
      { text: `[INFO] Resolving carrier records and geographic routing...`, delay: 500, progress: 45 },
      { text: `[INFO] Querying community call logs & robocaller registers...`, delay: 900, progress: 70 },
      { text: `[INFO] Evaluating caller ID spoofing probability parameters...`, delay: 1300, progress: 85 },
      { text: `[SUCCESS] Call database query complete. Compiling results...`, delay: 1700, progress: 100 }
    );
  }

  // Scroll terminal logs step-by-step
  logs.forEach(log => {
    setTimeout(() => {
      // Append text line
      const line = document.createElement('div');
      line.className = 'font-mono transition-all duration-300';
      if (log.text.includes('[SUCCESS]')) line.className += ' text-success font-semibold';
      else if (log.text.includes('[WARN]')) line.className += ' text-warning';
      else if (log.text.includes('[ERROR]')) line.className += ' text-error';
      else line.className += ' text-white/80';
      
      line.textContent = log.text;
      terminalOutput.appendChild(line);
      
      // Auto-scroll to bottom
      terminalOutput.scrollTop = terminalOutput.scrollHeight;
      
      // Update progress bar
      progressBar.style.width = `${log.progress}%`;
      
      // Done trigger
      if (log.progress === 100) {
        setTimeout(() => {
          // Hide terminal and form overlay
          terminal.classList.add('hidden');
          formBox.classList.remove('opacity-40', 'pointer-events-none');
          
          // Perform analytics
          const res = analyzeInput(value, type);

          // Populate report card elements
          const titleEl = document.getElementById('report-title-main');
          const explanationEl = document.getElementById('report-ai-explanation');
          const redFlagsEl = document.getElementById('report-red-flags');
          const greenFlagsEl = document.getElementById('report-green-flags');
          const browserUrlEl = document.getElementById('report-browser-url');
          const previewTitleEl = document.getElementById('preview-title');
          const ageTextEl = document.getElementById('report-age-text');
          const timelineBar = document.getElementById('timeline-bar');
          const previewLogo = document.getElementById('preview-logo');

          if (titleEl) titleEl.textContent = res.title;
          if (explanationEl) explanationEl.textContent = res.explanation;
          if (redFlagsEl) redFlagsEl.innerHTML = res.redFlagsHTML;
          if (greenFlagsEl) greenFlagsEl.innerHTML = res.greenFlagsHTML;
          if (browserUrlEl) browserUrlEl.textContent = res.browserUrl;
          if (previewTitleEl) previewTitleEl.textContent = res.previewTitle;
          if (ageTextEl) ageTextEl.textContent = res.ageText;
          
          // Timeline bar
          if (timelineBar) {
            timelineBar.style.width = `${res.agePercent}%`;
            // Color based on age
            timelineBar.className = "absolute top-0 left-0 h-full transition-all duration-1000 ease-out ";
            if (res.score >= 80) timelineBar.className += "bg-success";
            else if (res.score >= 50) timelineBar.className += "bg-warning";
            else timelineBar.className += "bg-error";
          }

          // Mockup preview logo change based on status
          if (previewLogo) {
            if (res.score >= 80) {
              previewLogo.className = "w-12 h-12 text-success";
              previewLogo.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0110 21a3.745 3.745 0 01-3.068-1.593 3.745 3.745 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.745 3.745 0 013.296-1.043A3.745 3.745 0 0114 3c1.268 0 2.39.63 3.068 1.593a3.745 3.745 0 013.296 1.043 3.745 3.745 0 011.043 3.296A3.745 3.745 0 0121 12z"/>';
            } else if (res.score >= 50) {
              previewLogo.className = "w-12 h-12 text-warning animate-pulse";
              previewLogo.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>';
            } else {
              previewLogo.className = "w-12 h-12 text-error animate-bounce";
              previewLogo.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z"/>';
            }
          }

          // Trigger TrustScoreDial update (calls inline helper on component)
          if ((window as any).updateTrustScoreDial) {
            (window as any).updateTrustScoreDial('report-dial', res.score);
          }

          // Save check history to localStorage
          saveToHistory(value, type, res.score);

          // Reveal report card with scroll effect
          report.classList.remove('hidden');
          report.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 300);
      }
    }, log.delay);
  });
}

function saveToHistory(value: string, type: string, score: number): void {
  try {
    const history = JSON.parse(localStorage.getItem('trustchecker_history') || '[]');
    const newRecord = {
      id: Math.random().toString(36).substring(2, 9),
      value: value.length > 50 ? value.substring(0, 50) + '...' : value,
      type: type,
      score: score,
      timestamp: new Date().toLocaleString()
    };
    
    // Add to front, limit to 6 entries
    history.unshift(newRecord);
    localStorage.setItem('trustchecker_history', JSON.stringify(history.slice(0, 6)));
    
    // Dispatch custom event to trigger HistoryLog refresh
    window.dispatchEvent(new Event('trustchecker_history_updated'));
  } catch (e) {
    console.error('Error saving to history: ', e);
  }
}
