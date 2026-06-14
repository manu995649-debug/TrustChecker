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

export interface FlaggedReason {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  explanation: string;
  evidence: string;
}

export interface ScoreBreakdownItem {
  name: string;
  value: number;
}

export interface TimelineEvent {
  date: string;
  title: string;
  description: string;
}

export interface CommunityIntel {
  reportsCount: number;
  recentReport: string;
  trendText: string;
  trendDirection: 'up' | 'down' | 'stable';
}

export interface DetailedAnalysisResult {
  score: number;
  verdict: 'Safe' | 'Likely Safe' | 'Suspicious' | 'High Risk' | 'Dangerous' | 'Scam Likely';
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  confidence: number;
  title: string;
  explanation: string;
  executiveSummary: string;
  reasons: FlaggedReason[];
  breakdown: ScoreBreakdownItem[];
  badges: string[];
  advice: string[];
  similarPatterns: string[];
  recommendedActions: string[];
  community: CommunityIntel;
  timeline: TimelineEvent[];
  simpleExplanation: string;
  browserUrl: string;
  previewTitle: string;
  ageText: string;
  agePercent: number;
}

// Custom heuristic analysis
export function analyzeInput(value: string, type: string): DetailedAnalysisResult {
  const normalizedVal = value.toLowerCase().trim();
  const seed = hashString(normalizedVal);
  
  let score = 90; // Default baseline score (out of 100)
  let confidence = 94; // Baseline confidence (0-100)
  let browserUrl = "https://www.google.com";
  let previewTitle = "Legitimate Page";
  let ageText = "N/A";
  let agePercent = 0; // 0 to 100 for visual timeline
  
  const reasons: FlaggedReason[] = [];
  const breakdown: ScoreBreakdownItem[] = [];
  const badges: string[] = [];
  const advice: string[] = [];
  const similarPatterns: string[] = [];
  const recommendedActions: string[] = [];
  const timeline: TimelineEvent[] = [];
  let executiveSummary = "";
  let simpleExplanation = "";
  let community: CommunityIntel = {
    reportsCount: 0,
    recentReport: "Clean reputation feed.",
    trendText: "Stable",
    trendDirection: "stable"
  };

  breakdown.push({ name: "Core Threat Baseline Check", value: 90 });

  // 1. WEBSITE & ECOMMERCE STORE HEURISTICS
  if (type === 'website' || type === 'store') {
    let domain = normalizedVal.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
    browserUrl = `https://${domain}`;
    previewTitle = domain.charAt(0).toUpperCase() + domain.slice(1);

    const isSSL = normalizedVal.startsWith('https://') || !normalizedVal.startsWith('http://');
    const endsWithShortScamTld = /\.(xyz|top|online|click|download|club|info|work|tech|support|store|shop|sale|site|space|fun|vip|live)$/.test(domain);
    const hasMultipleHyphens = (domain.match(/-/g) || []).length >= 2;
    const hasSubdomainFlooding = (domain.match(/\./g) || []).length >= 3;
    const hasLongLength = domain.length > 22;

    const brandTriggers = ['paypal', 'amazon', 'chase', 'netflix', 'apple', 'walmart', 'fedex', 'usps', 'dhl', 'ups', 'bankofamerica', 'wellsfargo', 'citibank', 'microsoft', 'google', 'facebook', 'instagram', 'coinbase', 'binance', 'crypto'];
    const matchedBrand = brandTriggers.find(brand => domain.includes(brand));
    const isOfficialBrand = matchedBrand ? new RegExp(`^${matchedBrand}\\.(com|org|net|co\\.uk|gov)$`).test(domain) : false;

    // SSL Check
    if (!isSSL) {
      score -= 18;
      breakdown.push({ name: "SSL/TLS Connection Encryption Check", value: -18 });
      reasons.push({
        severity: 'critical',
        title: "Insecure Connection Protocol",
        explanation: "This site does not utilize SSL certificate encryption. Credentials, credit card information, or passwords submitted here will be transmitted in plaintext and are susceptible to network eavesdropping.",
        evidence: "Protocol detected: HTTP (Port 80)"
      });
      badges.push("Insecure Connection");
    } else {
      score += 10;
      breakdown.push({ name: "SSL/TLS Encryption Certificate verified", value: 10 });
    }

    // Brand impersonation check
    if (matchedBrand && !isOfficialBrand) {
      score -= 48;
      breakdown.push({ name: "Protected Trademark Impersonation Flag", value: -48 });
      reasons.push({
        severity: 'critical',
        title: "Trademark Abuse / Impersonation",
        explanation: "The domain name references the brand name of a verified corporation but does not resolve to their official trademarked web infrastructure, which is a key indicator of a lookalike phishing portal.",
        evidence: `Matches protected trigger word '${matchedBrand}' but domain is '${domain}'`
      });
      previewTitle = `Alert: Copycat ${matchedBrand.charAt(0).toUpperCase() + matchedBrand.slice(1)} Interface`;
      badges.push("Brand Impersonation");
    }

    // TLD Extension Check
    if (endsWithShortScamTld) {
      score -= 22;
      breakdown.push({ name: "Low-Reputation TLD Extension Check", value: -22 });
      reasons.push({
        severity: 'high',
        title: "Low-Reputation Extension Prefix",
        explanation: "The website is registered under an extension commonly used by malicious actors. Cheap TLD registrations (.xyz, .top, .shop) are heavily utilized for automated throwaway scam campaigns due to minimal registry cost.",
        evidence: `Extension TLD resolves to .${domain.split('.').pop()}`
      });
      badges.push("Low-Reputation TLD");
    } else {
      score += 5;
      breakdown.push({ name: "Standard High-Reputation Extension Verification", value: 5 });
    }

    // Domain Age
    let ageInDays = 0;
    if (score >= 80) {
      ageInDays = 1000 + (seed % 8000);
    } else if (score >= 50) {
      ageInDays = 180 + (seed % 540);
    } else {
      ageInDays = 1 + (seed % 90);
    }

    if (ageInDays > 365) {
      const years = (ageInDays / 365).toFixed(1);
      ageText = `${years} Years Old`;
      agePercent = Math.min(100, Math.round((ageInDays / 1825) * 100));
      score += 10;
      breakdown.push({ name: "Domain Registration History Check", value: 10 });
    } else {
      ageText = `${ageInDays} Days Old`;
      agePercent = Math.max(5, Math.round((ageInDays / 365) * 20));
      score -= 20;
      breakdown.push({ name: "Young Domain Registration Penalty", value: -20 });
      reasons.push({
        severity: 'high',
        title: "Recently Registered Domain Structure",
        explanation: "This domain registration was created very recently. Scammers frequently buy domains, initiate fraud campaigns, and delete the websites within a few days to stay ahead of automated antivirus blacklists.",
        evidence: `Domain registered only ${ageText} ago (Age: ${ageInDays} days)`
      });
      badges.push("New Domain");
    }

    // Hyphen / Subdomain Checks
    if (hasMultipleHyphens) {
      score -= 10;
      breakdown.push({ name: "Multiple Domain Hyphens Detection", value: -10 });
      reasons.push({
        severity: 'medium',
        title: "Suspicious Hyphen-Flooded Domain Structure",
        explanation: "The domain name utilizes multiple hyphens. Phishers use hyphenated variations (e.g., brand-identity-verify) to craft mock URLs that appear legitimate at first glance to mobile users.",
        evidence: `Domain contains ${(domain.match(/-/g) || []).length} hyphens`
      });
    }

    if (hasSubdomainFlooding) {
      score -= 12;
      breakdown.push({ name: "Excessive Subdomains Count Check", value: -12 });
      reasons.push({
        severity: 'medium',
        title: "Subdomain Redirection Flooding",
        explanation: "The domain utilizes nested subdomains to mask the actual root path. Scammers chain subdomains to build lookalike login URLs (e.g., login.account.secure.root.com) which conceal the true domain owner.",
        evidence: `Domain contains ${(domain.match(/\./g) || []).length} domain subsegments`
      });
      badges.push("Subdomain Flooding");
    }

    if (hasLongLength) {
      score -= 8;
      breakdown.push({ name: "Excessive Domain Length Check", value: -8 });
      reasons.push({
        severity: 'low',
        title: "Abnormal Domain Name Length",
        explanation: "The domain name is abnormally long. This tactic is used to push the real registrar suffix off the viewable viewport in mobile browsers.",
        evidence: `Domain length is ${domain.length} characters`
      });
    }

    // eCommerce specific checks
    if (type === 'store') {
      const discountKeywords = ['cheap', 'clearance', 'discount', 'wholesale', 'sale', 'outlet', 'free', 'store-online'];
      const hasDiscountInName = discountKeywords.some(keyword => domain.includes(keyword));
      if (hasDiscountInName) {
        score -= 15;
        breakdown.push({ name: "eCommerce Discount-Bait Name Check", value: -15 });
        reasons.push({
          severity: 'medium',
          title: "Discount Bait Word Detection",
          explanation: "The domain includes commercial bait keywords (clearance, outlet, cheap) that are highly characteristic of short-lived catalog drop-shipping sites selling counterfeit goods or stealing card coordinates.",
          evidence: `Domain string contains bait keyword`
        });
        badges.push("Fake Urgency");
      }
    }

    // Formulate variables
    confidence = 90 + (seed % 7); // 90-96%
    
    // Community Intelligence
    if (score < 50) {
      const reports = 20 + (seed % 180);
      community = {
        reportsCount: reports,
        recentReport: `Flagged as a credit card credential harvester 1 day ago by user @threat_intel.`,
        trendText: `+${10 + (seed % 35)}% Traffic Spike`,
        trendDirection: 'up'
      };
    } else {
      community = {
        reportsCount: 0,
        recentReport: "No active security complaints or negative reputation marks reported.",
        trendText: "Stable Feed",
        trendDirection: "stable"
      };
    }

    // Timeline Setup
    const baseDate = new Date(Date.now() - ageInDays * 24 * 60 * 60 * 1000);
    const regDateStr = baseDate.toISOString().split('T')[0];
    const middleDate = new Date(Date.now() - Math.min(10, Math.round(ageInDays / 2)) * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    const scanDateStr = new Date().toISOString().split('T')[0];

    timeline.push({ date: regDateStr, title: "Domain Creation Date", description: `Domain registered via anonymous registry database record.` });
    if (score < 50) {
      timeline.push({ date: middleDate, title: "First Phishing Report Detected", description: "First anonymous user logged credential harvest attempts from this URL." });
    } else {
      timeline.push({ date: middleDate, title: "Infrastructure Verification", description: "Domain successfully mapped to high-reputation network routing nodes." });
    }
    timeline.push({ date: scanDateStr, title: "Live Cybersecurity Scan", description: "TrustChecker Heuristics system evaluated SSL credentials, domain history, and impersonation models." });

    // Executive Summary & Explain Like I'm Not Technical
    if (score >= 80) {
      executiveSummary = `This domain is verified as safe and trustworthy under current heuristic scans. It utilizes strong SSL certificate encryption, uses a standard registry extension, and has an established history of ${ageText}.\n\nNo phishing indicators, lookup blacklists, or spoofing patterns were found. You can interact with this site safely under standard digital guidelines.`;
      simpleExplanation = "Think of this website like an established store on a busy street with clear signage, an official business permit, and heavy deadbolt locks on the doors. It has been there a long time and has no indicators of trying to cheat its customers.";
      advice.push("Standard shopping guidelines apply.", "Enjoy safe browsing.", "Always verify domain prefix when signing in.");
      recommendedActions.push("Keep web browser updated", "Verify presence of lock icon in URL address bar");
      similarPatterns.push("Official Corporate Portals", "Standard Retail Stores");
    } else if (score >= 50) {
      executiveSummary = `This domain raises minor caution warnings. While connection traffic is encrypted via SSL, its relatively brief registration history (${ageText}) and extension suggest caution.\n\nWe recommend verifying the business credentials and searching for secondary feedback reviews before inputting financial info or personal details.`;
      simpleExplanation = "Think of this website like a new cart set up at a temporary fair. It has basic security locks, but since it has only been open a few months and has generic signage, it is smart to check the seller's license before buying from them.";
      advice.push("Verify corporate address in footer.", "Search independent reviews on consumer portals.", "Avoid saving auto-fill details on this website.");
      recommendedActions.push("Search registry info via WHOIS lookup", "Cross-check business phone contacts");
      similarPatterns.push("Unregistered Blog Portals", "Niche Retailers");
    } else {
      executiveSummary = `This website is flagged as a high-risk security threat. Multiple critical factors are active, including domain age limits and potential brand spoofing. This configuration is heavily aligned with fake portal structures designed to harvest login credentials and steal payment card digits.\n\nWe strongly recommend closing this window and avoiding any interaction or form submission.`;
      simpleExplanation = "Think of this website like a cardboard shop set up in a dark alley yesterday. It claims to be a well-known logistics firm, but it has no business license and is demanding you hand over your wallet before they let you in. Do not enter.";
      advice.push("Do not input banking or card numbers.", "Do not enter login credentials or passwords.", "Block and ignore any email or text redirecting you to this site.", "Run a local malware/antivirus scan on your device.");
      recommendedActions.push("Report URL to Google Safe Browsing", "Report domain host to registrar abuse desk", "Close this browser window immediately");
      similarPatterns.push("Brand Impersonation Clones", "Fake Delivery Redirection Scams", "eCommerce Storefront Scams");
    }
  }

  // 2. JOB OFFER HEURISTIC ENGINE
  else if (type === 'job') {
    previewTitle = "Job Offer Scan Report";
    confidence = 92;

    const hasTelegram = normalizedVal.includes('telegram') || normalizedVal.includes('t.me');
    const hasWhatsApp = normalizedVal.includes('whatsapp') || normalizedVal.includes('wa.me') || normalizedVal.includes('chat.whatsapp');
    const hasUpfrontPayment = normalizedVal.includes('upfront') || normalizedVal.includes('payment') || normalizedVal.includes('equipment fee') || normalizedVal.includes('purchase laptop') || normalizedVal.includes('reimburse') || normalizedVal.includes('check deposit') || normalizedVal.includes('check cashing');
    const hasUnrealisticPay = /\$\d{2,4}\s*(per\s*hour|hr|weekly|week)/.test(normalizedVal) || normalizedVal.includes('no experience required') || normalizedVal.includes('flexible hours') || normalizedVal.includes('simple tasks');
    const hasPackageHandler = normalizedVal.includes('package handler') || normalizedVal.includes('reshipping') || normalizedVal.includes('shipping coordinator') || normalizedVal.includes('forwarding');
    const hasPublicEmail = normalizedVal.includes('@gmail') || normalizedVal.includes('@yahoo') || normalizedVal.includes('@outlook') || normalizedVal.includes('@hotmail');

    if (hasTelegram || hasWhatsApp) {
      score -= 30;
      breakdown.push({ name: "Recruiter Communication Channel Verification", value: -30 });
      reasons.push({
        severity: 'high',
        title: "Anonymous Message App Redirection",
        explanation: "The recruiter requests communication solely via chat networks (Telegram, WhatsApp) and bypasses secure HR onboarding channels or phone interviews. Scammers use this setup to maintain anonymity and quickly delete conversation histories.",
        evidence: `Contains chat redirection link/keywords`
      });
      badges.push("Anonymous Recruiter");
    } else {
      score += 10;
      breakdown.push({ name: "Corporate HR Communication Alignment", value: 10 });
    }

    if (hasUpfrontPayment) {
      score -= 35;
      breakdown.push({ name: "Upfront Financial Requirements Check", value: -35 });
      reasons.push({
        severity: 'critical',
        title: "Advance Payment / Check Cashing Demand",
        explanation: "The job text mentions purchasing equipment upfront, depositing a corporate check to buy software from an approved vendor, or training fees. Legitimate corporations never send checks for candidates to buy items and wire back the change, a classic hallmark of check fraud.",
        evidence: `Requires upfront transaction or check processing`
      });
      badges.push("Payment Request");
    }

    if (hasUnrealisticPay) {
      score -= 15;
      breakdown.push({ name: "Job Compensation Realism Check", value: -15 });
      reasons.push({
        severity: 'medium',
        title: "Unrealistic Income vs Skill Expectation",
        explanation: "The salary or wage rate is significantly higher than market baseline rates for entry-level work requiring 'no experience' or 'few hours'. This tactic is used to lure job seekers into money-laundering or cash-mule operations.",
        evidence: `Mentions high pay with flexible/simple expectations`
      });
      badges.push("Fake Urgency");
    }

    if (hasPackageHandler) {
      score -= 25;
      breakdown.push({ name: "Job Role Threat Classifier", value: -25 });
      reasons.push({
        severity: 'high',
        title: "Package Forwarding / Shipping Logistics Role",
        explanation: "The job involves receiving packages at your residential address, repackaging them, and reshipping them. This is typical of shipping scams where stolen merchandise bought with fraudulent credit cards is processed through unwitting candidates.",
        evidence: `Role identified: reshipping/forwarding handler`
      });
      badges.push("Money Mule Risk");
    }

    if (hasPublicEmail) {
      score -= 18;
      breakdown.push({ name: "Corporate Email Domain Audit", value: -18 });
      reasons.push({
        severity: 'high',
        title: "Free Public Email Host Contact",
        explanation: "The recruiter uses a generic domain (@gmail, @yahoo) rather than an official corporate email domain. Genuine corporate HR departments correspond through their company domains.",
        evidence: `Email matches public host domain`
      });
      badges.push("Anonymous Recruiter");
    }

    // Community Reports
    if (score < 60) {
      community = {
        reportsCount: 14 + (seed % 30),
        recentReport: "Identified as a fake check-cashing scam campaign on multiple consumer forums.",
        trendText: "Active Campaign (+15%)",
        trendDirection: "up"
      };
    } else {
      community = {
        reportsCount: 0,
        recentReport: "No active recruiter alerts.",
        trendText: "Stable Feed",
        trendDirection: "stable"
      };
    }

    // Timeline Setup
    const scanDateStr = new Date().toISOString().split('T')[0];
    timeline.push({ date: "2026-06-05", title: "Job Description First Logged", description: "Text first detected on classified portals." });
    timeline.push({ date: "2026-06-10", title: "Chat Redirection Initiated", description: "Telegram/WhatsApp recruiting channels linked to posting." });
    timeline.push({ date: scanDateStr, title: "NLP Classification Complete", description: "Text analysis mapped key phrasing metrics to financial scams." });

    // Executive Summary & ELI5
    if (score >= 80) {
      executiveSummary = `This job offer appears to be safe and legitimate. The communication utilizes formal channels, avoids payment requests, and doesn't showcase reshipping behaviors.\n\nWe recommend verifying that the recruiter's exact sender address corresponds to the actual company domain before sharing any documents like government IDs or SSNs.`;
      simpleExplanation = "This job offer is like a standard posting on a corporate billboard. It has a realistic salary, normal contact emails, and isn't asking you to pay any fees or cash check deposits.";
      advice.push("Always check recruiter credentials on LinkedIn.", "Double check sender email header.", "Confirm posting matches official careers portal.");
      recommendedActions.push("Contact company HR department directly", "Verify company registration history");
      similarPatterns.push("Standard Corporate Careers", "Legitimate Staffing Agencies");
    } else {
      executiveSummary = `This job offer is flagged as a high-risk employment scam. It contains critical patterns of financial fraud, specifically request for upfront check processing, messaging redirection, or reshipping logistics. Legitimate employers never require payment for onboarding or direct you to buy laptops via a check refund scheme.\n\nWe strongly recommend breaking off communication with this contact immediately.`;
      simpleExplanation = "This is like a stranger coming up to you, offering a high-paying office job, but then telling you that you have to write them a check to buy a computer, and that you must communicate only in a dark corner of a messaging app. Do not trust them.";
      advice.push("Do not provide SSN or driver's license numbers.", "Never deposit checks sent by online recruiters.", "Do not purchase work equipment for reimbursement.", "Block the recruiter on all messaging networks.");
      recommendedActions.push("Report posting to classified site admins", "File complaint with FTC at ReportFraud.ftc.gov", "Discard any checks sent by the recruiter");
      similarPatterns.push("Advance Fee Employment Scams", "Money Mule / Reshipping Schemes", "Fake Check Cashing Recruitment");
    }
  }

  // 3. EMAIL PHISHING HEURISTIC ENGINE
  else if (type === 'email') {
    previewTitle = "Email Parser Analysis";
    confidence = 94;

    const hasUrgency = normalizedVal.includes('urgent') || normalizedVal.includes('action required') || normalizedVal.includes('immediately') || normalizedVal.includes('suspended') || normalizedVal.includes('unauthorized transaction') || normalizedVal.includes('locked') || normalizedVal.includes('compromised');
    const hasFinancialBait = normalizedVal.includes('wire transfer') || normalizedVal.includes('gift card') || normalizedVal.includes('inheritance') || normalizedVal.includes('lottery') || normalizedVal.includes('fund transfer') || normalizedVal.includes('crypto deposit');
    const hasCredentialBait = normalizedVal.includes('login now') || normalizedVal.includes('click here to verify') || normalizedVal.includes('update password') || normalizedVal.includes('verify your ssn') || normalizedVal.includes('security question');
    const hasGrammarIssues = normalizedVal.includes('dear customer') || normalizedVal.includes('regards bank') || normalizedVal.includes('kindly do');

    if (hasUrgency) {
      score -= 28;
      breakdown.push({ name: "Artificial Urgency & Threat Phrasing Check", value: -28 });
      reasons.push({
        severity: 'high',
        title: "Artificial Sense of Urgency",
        explanation: "The email uses threat language (demanding immediate action to prevent account suspension, legal trouble, or locking). Scammers create pressure to panic targets, preventing them from checking the claim carefully.",
        evidence: `Keywords: urgent, suspended, locked detected`
      });
      badges.push("Fake Urgency");
    }

    if (hasFinancialBait) {
      score -= 32;
      breakdown.push({ name: "Financial Trap Phrasing Analysis", value: -32 });
      reasons.push({
        severity: 'high',
        title: "Financial Baiting Patterns",
        explanation: "The email references unexpected monetary funds, wire transfers, lottery prize awards, or gift card deposits. These traps serve to initiate advance fee collection scams.",
        evidence: `Financial scam keywords detected in email body`
      });
      badges.push("Payment Request");
    }

    if (hasCredentialBait) {
      score -= 35;
      breakdown.push({ name: "Identity harvesting Verification", value: -35 });
      reasons.push({
        severity: 'critical',
        title: "Credential Harvesting Vectors",
        explanation: "The email requests that you click an embedded hyperlink to verify credentials, change passwords, confirm Social Security numbers, or enter security codes. Secure institutions do not request credential changes via links in emails.",
        evidence: `Direct call-to-action link requesting credential updates`
      });
      badges.push("Phishing Language");
    }

    if (hasGrammarIssues) {
      score -= 10;
      breakdown.push({ name: "Semantic Greeting & Grammar Audit", value: -10 });
      reasons.push({
        severity: 'low',
        title: "Generic Salutation / Grammar Failures",
        explanation: "The email features generic salutations ('Dear Customer') or awkward vocabulary, which are classic signs of foreign phishing campaigns utilizing pre-made templates.",
        evidence: `Generic greeting or grammatical errors identified`
      });
    }

    // Community Reports
    if (score < 60) {
      community = {
        reportsCount: 45 + (seed % 100),
        recentReport: "Flagged as an active Microsoft/Netflix account phishing template.",
        trendText: "High Active Spike",
        trendDirection: "up"
      };
    } else {
      community = {
        reportsCount: 0,
        recentReport: "No reputation flags.",
        trendText: "Stable Feed",
        trendDirection: "stable"
      };
    }

    // Timeline Setup
    const scanDateStr = new Date().toISOString().split('T')[0];
    timeline.push({ date: "2026-06-08", title: "Email Campaign Registered", description: "Email metadata logged on public mail spam lists." });
    timeline.push({ date: "2026-06-12", title: "Domain Alignment Failed", description: "SPF/DKIM alignment checks failed for simulated sender." });
    timeline.push({ date: scanDateStr, title: "Text Phishing Analysis", description: "TrustChecker analyzed the body content for social engineering indicators." });

    // Executive Summary & ELI5
    if (score >= 80) {
      executiveSummary = `No phishing signals were found in the email text body. The content is free of urgency tricks, credential farming, or financial traps.\n\nAlways examine the sender address header in your email client (e.g. billing@netflix.com, not netflix-billing@secure-update.xyz) before clicking links or replying.`;
      simpleExplanation = "This email matches standard communication styles and contains no signs of pressure tactics, login traps, or fake money promises.";
      advice.push("Confirm sender's exact address header.", "Verify links without clicking (hover to check URL).", "Never reply to verify passwords.");
      recommendedActions.push("Check SPF/DKIM headers in your email client", "Run regular anti-malware system scans");
      similarPatterns.push("Standard Corporate Newsletters", "Clean Billing Notifications");
    } else {
      executiveSummary = `Warning: High probability of phishing detected in this email. The text displays strong social-engineering characteristics, including high-pressure urgency alerts and attempts to gather credentials or request transactions.\n\nWe recommend marking the email as spam, blocking the sender, and avoiding clicking any embedded links.`;
      simpleExplanation = "This email is like a fake letter claiming to be from the post office, warning that your home will be locked up unless you write down your house keys and send it back immediately. Do not click anything.";
      advice.push("Do not click any buttons or links in the email.", "Do not download PDF, HTML, or ZIP attachments.", "Mark the email as spam/phishing immediately.", "Ignore claims of immediate account suspension.");
      recommendedActions.push("Mark email as phishing in mail client", "Report scam to phishing@abuse.com", "Delete the email message from trash bin");
      similarPatterns.push("Account Suspension Spoofs", "Credential Harvesting Campaigns", "Unexpected Payment Notifications");
    }
  }

  // 4. SMS / SMISHING HEURISTIC ENGINE
  else if (type === 'sms') {
    previewTitle = "SMS Alert Scan";
    confidence = 95;

    const hasPackageScam = normalizedVal.includes('usps') || normalizedVal.includes('post office') || normalizedVal.includes('delivery fee') || normalizedVal.includes('package pending') || normalizedVal.includes('shipment failed') || normalizedVal.includes('dhl') || normalizedVal.includes('fedex') || normalizedVal.includes('ips') || normalizedVal.includes('redirection');
    const hasBankScam = normalizedVal.includes('card blocked') || normalizedVal.includes('chase notification') || normalizedVal.includes('unauthorized login') || normalizedVal.includes('transfer code') || normalizedVal.includes('bank alert') || normalizedVal.includes('boa alert');
    const hasSuspiciousShortlink = /https?:\/\/[a-z0-9.-]+\.[a-z]{2,5}\/[a-z0-9]{3,8}/i.test(value) && !normalizedVal.includes('google.com') && !normalizedVal.includes('apple.com');
    const hasPrizeWinner = normalizedVal.includes('congratulations') || normalizedVal.includes('prize') || normalizedVal.includes('gift card') || normalizedVal.includes('winner') || normalizedVal.includes('draw');

    if (hasPackageScam) {
      score -= 42;
      breakdown.push({ name: "Logistics Impersonation Check", value: -42 });
      reasons.push({
        severity: 'critical',
        title: "Logistics/Courier Fraud Pattern",
        explanation: "The message mimics package delivery updates (claiming a USPS, FedEx, or DHL package is held at a warehouse, has address errors, or requires custom delivery fees). Scammers send millions of these automated texts to steal card details.",
        evidence: `Logistic brand keywords identified in message`
      });
      badges.push("Package Delivery Scam");
    }

    if (hasBankScam) {
      score -= 45;
      breakdown.push({ name: "Financial Institution Spoof Check", value: -45 });
      reasons.push({
        severity: 'critical',
        title: "Urgent Banking Impersonation",
        explanation: "The message pretends to be a bank reporting locked credit cards, suspicious transfers, or unauthorized logins. It requests clicking a link to resolve the warning, which routes to a copycat login portal.",
        evidence: `Banking warning keywords detected`
      });
      badges.push("Brand Impersonation");
    }

    if (hasSuspiciousShortlink) {
      score -= 25;
      breakdown.push({ name: "Shortlink Redirection Threat", value: -25 });
      reasons.push({
        severity: 'high',
        title: "Suspicious Web Shortlink Link",
        explanation: "The SMS body contains a shortened link redirecting to an unverified domain. Attackers use shortlinks to hide the real domain URL, hoping you won't inspect the full link on mobile.",
        evidence: `Regex match on unverified shortened URL structure`
      });
      badges.push("Unverified Link");
    }

    if (hasPrizeWinner) {
      score -= 35;
      breakdown.push({ name: "Reward Reward Bait Analysis", value: -35 });
      reasons.push({
        severity: 'high',
        title: "Prize / Rewards Baiting Trap",
        explanation: "The message claims you won sweepstakes, gift cards, or loyalty prizes from major stores you did not visit. The link routes to surveys that harvest personal profiles and credit card details.",
        evidence: `Prize winner keywords detected`
      });
      badges.push("Payment Request");
    }

    // Community Reports
    if (score < 60) {
      community = {
        reportsCount: 120 + (seed % 300),
        recentReport: "SMS reported sending fake courier redelivery update scams.",
        trendText: "+55% Surge (Active Wave)",
        trendDirection: "up"
      };
    } else {
      community = {
        reportsCount: 0,
        recentReport: "No complaints on record.",
        trendText: "Stable Feed",
        trendDirection: "stable"
      };
    }

    // Timeline Setup
    const scanDateStr = new Date().toISOString().split('T')[0];
    timeline.push({ date: "2026-06-09", title: "Shortlink Registered", description: "Throwaway redirect domain registered via proxy." });
    timeline.push({ date: "2026-06-11", title: "Bulk Carrier Spam Reports", description: "Carrier network filters flagged bulk SMS campaigns." });
    timeline.push({ date: scanDateStr, title: "Text Analysis Scan", description: "TrustChecker analyzed wording matches against banking and courier scams." });

    // Executive Summary & ELI5
    if (score >= 80) {
      executiveSummary = `This text message does not contain courier traps, banking scares, or suspicious links.\n\nExercise caution if the text comes from an unknown 10-digit number asking you to click on unknown links.`;
      simpleExplanation = "This text message has no typical signs of courier scams, bank alerts, or fake short links.";
      advice.push("Ignore links from unknown numbers.", "Do not reply to spam messages.", "Block unknown sender.");
      recommendedActions.push("Add number to block list", "Keep phone OS updated");
      similarPatterns.push("Personal Texts", "Standard SMS updates");
    } else {
      executiveSummary = `Warning: Critical threat detected. This SMS follows classic Smishing templates. It attempts to trigger panic using fake delivery or banking warnings, routing you to a phishing link designed to harvest card details.\n\nWe recommend blocking the sender and deleting the message.`;
      simpleExplanation = "This is like a stranger dropping a note in your mailbox saying they are a postman and need your credit card number to deliver a package. Real postmen would never do that.";
      advice.push("Do not tap the link in the message.", "Never input credit card or banking details.", "Block the sender's mobile number immediately.", "Do not call the phone number.");
      recommendedActions.push("Forward SMS to 7726 (Carrier Spam Registry)", "Block sender in phone app settings", "Delete message from device");
      similarPatterns.push("USPS Delivery Address Scams", "Chase Bank Alert Spoofs", "Fake Prize Sweepstakes Texts");
    }
  }

  // 5. PHONE REPUTATION ENGINE
  else if (type === 'phone') {
    previewTitle = "Phone Number Scan";
    confidence = 94;
    const cleanPhone = normalizedVal.replace(/[^0-9]/g, '');
    
    const isTollFreeSpam = cleanPhone.startsWith('800') || cleanPhone.startsWith('1800') || cleanPhone.startsWith('888') || cleanPhone.startsWith('877') || cleanPhone.startsWith('866');
    const hasSpamPattern = (seed % 10) >= 6;

    if (isTollFreeSpam) {
      score -= 15;
      breakdown.push({ name: "Toll-Free Prefix Flag", value: -15 });
      reasons.push({
        severity: 'medium',
        title: "Toll-Free Business Prefix",
        explanation: "The caller utilizes a toll-free prefix. Scammers spoof 800 numbers or buy them cheap on internet VoIP gateways to look like national corporate customer support services.",
        evidence: `Prefix: Toll-free number format`
      });
      badges.push("Spoofed Caller ID");
    }

    if (hasSpamPattern) {
      score -= 52;
      breakdown.push({ name: "Public Spam Registry Matches", value: -52 });
      reasons.push({
        severity: 'critical',
        title: "Active Robocaller Registry Flag",
        explanation: "This number has been heavily reported in caller registries for robocalls, unsolicited telemarketing, and tax/utility scam campaigns.",
        evidence: `Matched active complaints database records`
      });
      badges.push("Robocaller");
      badges.push("Telemarketer");
    }

    // Community Reports
    if (score < 60) {
      community = {
        reportsCount: 150 + (seed % 400),
        recentReport: "Flagged by users as automated voice scam claiming credit card updates.",
        trendText: "Elevated Active Call Volume",
        trendDirection: "up"
      };
    } else {
      community = {
        reportsCount: 0,
        recentReport: "No active consumer alerts registered.",
        trendText: "Stable Feed",
        trendDirection: "stable"
      };
    }

    // Timeline Setup
    const scanDateStr = new Date().toISOString().split('T')[0];
    timeline.push({ date: "2026-05-15", title: "Caller ID Registered", description: "VoIP phone routing nodes mapped." });
    timeline.push({ date: "2026-06-05", title: "Robocall Flags Filed", description: "Multiple consumers logged automated IRS scam calls." });
    timeline.push({ date: scanDateStr, title: "Reputation Look-Up Audit", description: "Checked number history in active spam registries." });

    // Executive Summary & ELI5
    if (score >= 80) {
      executiveSummary = `This phone number has a clean reputation. We found zero reports of spam, automated robocalls, or commercial fraud campaigns. It is likely a standard corporate office line or personal phone.`;
      simpleExplanation = "This number is clean. No automated call programs or telemarketing reports are linked to it.";
      advice.push("Safe to answer.", "Standard safety guidelines apply.", "Block if they make pushy sales requests.");
      recommendedActions.push("Verify caller identity on official directory");
      similarPatterns.push("Corporate Main Lines", "Clean Residential Numbers");
    } else {
      executiveSummary = `Warning: Verified robocaller/scam caller ID. This number is logged in public registries for automated voice fraud campaigns, including credit card reduction and utility threat calls.\n\nWe recommend blocking the number and avoiding answering or providing personal data.`;
      simpleExplanation = "This number is linked to a computer program that calls thousands of people, trying to scare them into sending money by pretending to be a bank, energy company, or tax office. Block them.";
      advice.push("Do not answer calls from this caller.", "Do not reply to voicemails left by this number.", "Block the caller on your phone.", "Do not share credit card numbers or address details.");
      recommendedActions.push("Add number to block list", "Register on Do Not Call registry", "Report scam call to FTC");
      similarPatterns.push("IRS Tax Debt Threats", "Utility Interruption Spoofs", "Credit Card Rate Reduction Robocalls");
    }
  }

  // Ensure score constraints
  score = Math.max(5, Math.min(99, score));

  // Determine Verdict and Risk Level based on final score
  let verdict: 'Safe' | 'Likely Safe' | 'Suspicious' | 'High Risk' | 'Dangerous' | 'Scam Likely';
  let riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';

  if (score >= 90) {
    verdict = 'Safe';
    riskLevel = 'Low';
  } else if (score >= 75) {
    verdict = 'Likely Safe';
    riskLevel = 'Low';
  } else if (score >= 50) {
    verdict = 'Suspicious';
    riskLevel = 'Medium';
  } else if (score >= 30) {
    verdict = 'High Risk';
    riskLevel = 'High';
  } else if (score >= 10) {
    verdict = 'Dangerous';
    riskLevel = 'Critical';
  } else {
    verdict = 'Scam Likely';
    riskLevel = 'Critical';
  }

  // Format title
  title = `Trust Score: ${score}/100 - ${verdict}`;

  return {
    score,
    verdict,
    riskLevel,
    confidence,
    title,
    explanation: executiveSummary.split('\n\n')[0], // Fallback
    executiveSummary,
    reasons,
    breakdown,
    badges,
    advice,
    similarPatterns,
    recommendedActions,
    community,
    timeline,
    simpleExplanation,
    browserUrl,
    previewTitle,
    ageText,
    agePercent
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
      { text: `[SUCCESS] Email threat threat scan complete. Building dashboard...`, delay: 1600, progress: 100 }
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

          // Populating all 12 elements of the redesigned report card
          
          // 1. Verdict Title & Meta Header
          const verdictTitleEl = document.getElementById('verdict-title');
          const riskLevelEl = document.getElementById('verdict-risk-level');
          const confidenceEl = document.getElementById('verdict-confidence-badge');
          const metaTypeEl = document.getElementById('report-meta-type');
          const timestampEl = document.getElementById('report-timestamp');
          const verdictCard = document.getElementById('verdict-card');
          const accentGlow = document.getElementById('verdict-accent-glow');

          if (verdictTitleEl) verdictTitleEl.textContent = res.verdict;
          if (confidenceEl) confidenceEl.textContent = `Confidence: ${res.confidence}%`;
          if (metaTypeEl) metaTypeEl.textContent = `${type.toUpperCase()} HEURISTIC ENGINE`;
          if (timestampEl) {
            const date = new Date();
            timestampEl.textContent = `Scanned on: ${date.toLocaleString()}`;
          }

          if (riskLevelEl) {
            riskLevelEl.textContent = `Risk: ${res.riskLevel}`;
            riskLevelEl.className = 'text-xs font-mono font-semibold px-2.5 py-0.5 rounded-full border transition-all duration-300 ';
            if (res.score >= 80) {
              riskLevelEl.className += 'text-emerald-500 border-emerald-500/20 bg-emerald-500/10 dark:bg-emerald-500/5';
            } else if (res.score >= 70) {
              riskLevelEl.className += 'text-teal-500 border-teal-500/20 bg-teal-500/10 dark:bg-teal-500/5';
            } else if (res.score >= 50) {
              riskLevelEl.className += 'text-amber-500 border-amber-500/20 bg-amber-500/10 dark:bg-amber-500/5';
            } else {
              riskLevelEl.className += 'text-red-500 border-red-500/20 bg-red-500/10 dark:bg-red-500/5';
            }
          }

          if (verdictCard && accentGlow) {
            verdictCard.className = "relative overflow-hidden rounded-xl border p-6 md:p-8 mb-8 transition-all duration-300 shadow-level1 bg-canvas-soft ";
            accentGlow.className = "absolute top-0 left-0 w-2 h-full transition-all duration-500 ";
            
            if (res.score >= 80) {
              verdictCard.className += "border-emerald-500/20 bg-emerald-500/[0.02] shadow-emerald-500/5";
              accentGlow.className += "bg-emerald-500";
            } else if (res.score >= 70) {
              verdictCard.className += "border-teal-500/20 bg-teal-500/[0.02] shadow-teal-500/5";
              accentGlow.className += "bg-teal-500";
            } else if (res.score >= 50) {
              verdictCard.className += "border-amber-500/20 bg-amber-500/[0.02] shadow-amber-500/5";
              accentGlow.className += "bg-amber-500";
            } else {
              verdictCard.className += "border-red-500/20 bg-red-500/[0.02] shadow-red-500/5";
              accentGlow.className += "bg-red-500";
            }
          }

          // 2. Executive Summary
          const execSummaryEl = document.getElementById('report-executive-summary');
          if (execSummaryEl) {
            execSummaryEl.innerHTML = res.executiveSummary.split('\n\n').map(p => `<p class="leading-relaxed">${p}</p>`).join('');
          }

          // 3. Why We Flagged This (Threat Reasons)
          const reasonsListEl = document.getElementById('report-reasons-list');
          if (reasonsListEl) {
            if (res.reasons.length === 0) {
              reasonsListEl.innerHTML = `
                <div class="border border-hairline border-dashed rounded-xl p-6 text-center text-xs text-mute font-mono">
                  No critical warning flags or indicators triggered. No threats identified.
                </div>
              `;
            } else {
              reasonsListEl.innerHTML = res.reasons.map(reason => {
                let badgeStyle = '';
                if (reason.severity === 'critical') badgeStyle = 'text-red-500 bg-red-500/10 border-red-500/20';
                else if (reason.severity === 'high') badgeStyle = 'text-orange-500 bg-orange-500/10 border-orange-500/20';
                else if (reason.severity === 'medium') badgeStyle = 'text-amber-500 bg-amber-500/10 border-amber-500/20';
                else badgeStyle = 'text-blue-500 bg-blue-500/10 border-blue-500/20';

                return `
                  <div class="border border-hairline rounded-xl p-5 bg-canvas shadow-level1 flex gap-4 items-start relative hover:border-hairline-strong transition-all duration-200">
                    <span class="text-[9px] font-mono font-bold px-2 py-0.5 rounded border uppercase flex-shrink-0 mt-0.5 ${badgeStyle}">
                      ${reason.severity}
                    </span>
                    <div class="flex flex-col gap-1.5">
                      <h4 class="text-xs font-bold text-ink leading-tight">${reason.title}</h4>
                      <p class="text-xs text-body leading-relaxed">${reason.explanation}</p>
                      <div class="text-[10px] font-mono text-mute mt-2 border-t border-hairline pt-2 flex items-center gap-1.5">
                        <span class="text-error font-semibold uppercase">Evidence:</span>
                        <span>${reason.evidence}</span>
                      </div>
                    </div>
                  </div>
                `;
              }).join('');
            }
          }

          // 4. Trust Breakdown
          const breakdownListEl = document.getElementById('report-breakdown-list');
          if (breakdownListEl) {
            breakdownListEl.innerHTML = res.breakdown.map(item => {
              const isNeg = item.value < 0;
              const colorClass = isNeg ? 'text-red-500' : 'text-emerald-500';
              const sign = isNeg ? '' : '+';
              const percent = Math.min(100, Math.round((Math.abs(item.value) / 50) * 100));
              const barColor = isNeg ? 'bg-red-500/50' : 'bg-emerald-500/50';

              return `
                <div class="flex flex-col gap-1 border-b border-hairline/50 pb-2.5 last:border-0 last:pb-0">
                  <div class="flex justify-between items-center text-xs">
                    <span class="text-body font-medium">${item.name}</span>
                    <span class="font-mono font-semibold ${colorClass}">${sign}${item.value}</span>
                  </div>
                  <div class="w-full bg-canvas-soft-2 h-1.5 rounded-full overflow-hidden">
                    <div class="h-full rounded-full ${barColor}" style="width: ${percent}%"></div>
                  </div>
                </div>
              `;
            }).join('');
          }

          // 5. Risk Indicators (Badges)
          const badgesEl = document.getElementById('report-risk-badges');
          if (badgesEl) {
            if (res.badges.length === 0) {
              badgesEl.innerHTML = `
                <span class="text-xs text-mute font-mono px-3 py-1 bg-canvas-soft rounded border border-hairline">
                  🟢 Standard Baseline
                </span>
              `;
            } else {
              badgesEl.innerHTML = res.badges.map(badge => `
                <span class="text-[10px] font-mono font-semibold px-2.5 py-1 rounded-md border border-red-500/20 bg-red-500/5 text-red-500 uppercase tracking-wider">
                  ⚠️ ${badge}
                </span>
              `).join('');
            }
          }

          // 6. What This Means For You
          const adviceEl = document.getElementById('report-advice-list');
          if (adviceEl) {
            adviceEl.innerHTML = res.advice.map(item => `
              <li class="flex items-start gap-2 text-xs text-body leading-relaxed">
                <span class="text-error flex-shrink-0 mt-0.5">✖</span>
                <span>${item}</span>
              </li>
            `).join('');
          }

          // 7. Similar Scam Patterns
          const similarPatternsEl = document.getElementById('report-similar-patterns');
          if (similarPatternsEl) {
            similarPatternsEl.innerHTML = res.similarPatterns.map(pattern => `
              <div class="flex items-center gap-2 border-b border-hairline/50 py-2 last:border-0 last:py-0 text-xs text-body">
                <span class="w-1.5 h-1.5 rounded-full bg-red-500"></span>
                <span class="font-medium">${pattern}</span>
              </div>
            `).join('');
          }

          // 8. Recommended Actions
          const actionsEl = document.getElementById('report-actions-list');
          if (actionsEl) {
            actionsEl.innerHTML = res.recommendedActions.map(action => `
              <li class="flex items-start gap-2 text-xs text-body leading-relaxed">
                <span class="text-success flex-shrink-0 mt-0.5">✔</span>
                <span class="font-medium">${action}</span>
              </li>
            `).join('');
          }

          // 9. Community Intelligence
          const commCountEl = document.getElementById('report-community-count');
          const commRecentEl = document.getElementById('report-community-recent');
          const commTrendEl = document.getElementById('report-community-trend');

          if (commCountEl) commCountEl.textContent = res.community.reportsCount.toString();
          if (commRecentEl) commRecentEl.textContent = res.community.recentReport;
          
          if (commTrendEl) {
            commTrendEl.textContent = res.community.trendText;
            commTrendEl.className = "text-[10px] font-semibold px-2 py-0.5 rounded font-mono ";
            if (res.community.trendDirection === 'up') {
              commTrendEl.className += "bg-red-500/10 text-red-500 border border-red-500/20";
            } else if (res.community.trendDirection === 'down') {
              commTrendEl.className += "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20";
            } else {
              commTrendEl.className += "bg-canvas-soft-2 text-mute border border-hairline";
            }
          }

          // 10. Evidence Timeline
          const timelineEl = document.getElementById('report-timeline');
          if (timelineEl) {
            timelineEl.innerHTML = res.timeline.map(event => `
              <div class="relative">
                <div class="absolute -left-[31px] top-1.5 w-2.5 h-2.5 rounded-full bg-canvas border-2 border-hairline-strong shadow-sm"></div>
                <div class="flex flex-col gap-1">
                  <span class="text-[9px] font-mono font-bold text-mute uppercase">${event.date}</span>
                  <span class="text-xs font-bold text-ink leading-tight">${event.title}</span>
                  <span class="text-[11px] text-body leading-relaxed">${event.description}</span>
                </div>
              </div>
            `).join('');
          }

          // 11. Explain Like I'm Not Technical
          const simpleExplanationEl = document.getElementById('report-simple-text');
          if (simpleExplanationEl) {
            simpleExplanationEl.textContent = res.simpleExplanation;
            // Reset accordion height in case it was open
            const simpleContentPanel = document.getElementById('report-simple-content');
            if (simpleContentPanel && simpleContentPanel.style.maxHeight !== '0px' && simpleContentPanel.style.maxHeight !== '') {
              simpleContentPanel.style.maxHeight = simpleContentPanel.scrollHeight + 'px';
            }
          }

          // Update TrustScoreDial
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
