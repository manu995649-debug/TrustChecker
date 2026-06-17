import type { APIRoute } from 'astro';

export const prerender = false;

// Interface matching client-side DetailedAnalysisResult
interface DetailedAnalysisResult {
  score: number;
  verdict: 'Safe' | 'Likely Safe' | 'Suspicious' | 'High Risk' | 'Dangerous' | 'Scam Likely';
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  confidence: number;
  title?: string;
  executiveSummary: string;
  findings: Array<{
    finding: string;
    whyItMatters: string;
    impact: string;
    confidence: 'High' | 'Medium' | 'Low';
  }>;
  positiveSignals: string[];
  negativeSignals: string[];
  scoreBreakdown: Array<{ name: string; value: number }>;
  redFlags: Array<{ title: string; description: string }>;
  whatItMeans: Array<{ advice: string; consequence: string }>;
  matchedPatterns: Array<{ pattern: string; similarity: string }>;
  recommendedActions: Array<{ action: string; reasoning: string }>;
  communityIntel: {
    reportsCount: number;
    complaints: string[];
    trendText: string;
    trendDirection: 'up' | 'down' | 'stable';
  };
  simpleExplanation: string;
}

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    // 1. Parse and validate input params
    const body = await request.json();
    const { value, type } = body;

    if (!value || typeof value !== 'string' || !type || typeof type !== 'string') {
      return new Response(JSON.stringify({ error: 'Missing or invalid parameters: value and type are required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 2. Fetch API key from server environment
    const cloudflareEnv = (locals as any).runtime?.env;
    const apiKey = cloudflareEnv?.GEMINI_API_KEY || import.meta.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY;
    if (!apiKey) {
      console.error('Server Configuration Error: GEMINI_API_KEY is not defined in the server environment.');
      return new Response(JSON.stringify({ error: 'Server configuration error: Threat scan API key is not configured.' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 3. Construct the prompt text
    const promptText = `
You are an expert threat intelligence analyst at a cybersecurity firm.
Analyze this suspicious input:
Input Type: ${type}
Input Content: "${value}"

Perform a forensic analysis. Answer these 5 questions:
1. Is it safe?
2. Why do you think that? (Explain indicators)
3. What evidence supports that?
4. Why should I care? (Detail specific vulnerabilities/consequences)
5. What should I do next? (Provide actionable next steps and reasoning)

COMPETITOR COMPARISON & SUPERIORITY INSTRUCTIONS:
- Analyze what standard threat checkers (e.g. VirusTotal, ScamAdviser, URLVoid, PhishTank, Whois lookup checkers) would report for this input.
- Compare and contrast our context-aware AI threat analysis against those standard checks. Note what generic databases/checkers would miss (e.g., they miss semantic context, lookalike domain homoglyphs, recruitment advance-fee patterns in conversations, high-urgency language, banking/courier smishing templates, VoIP caller routing masking).
- Integrate this comparison directly in your findings and executiveSummary. Make sure to explain clearly why our AI-driven report is more useful, accurate, and comprehensive than those static competitors.

IMPORTANT constraints:
- Do NOT use ChatGPT clichés like "Based on the provided information" or "As an AI".
- Sound authoritative, professional, and evidence-based.
- Keep all descriptions extremely concise (1-2 sentences max per description/field) to minimize generation latency.
- Return EXACTLY a JSON object matching this schema, with no other text:
{
  "score": number, // 0 to 100, where 90+ is Safe, 75-89 is Likely Safe, 50-74 is Suspicious, 30-49 is High Risk, 10-29 is Dangerous, and <10 is Scam Likely
  "verdict": "Safe" | "Likely Safe" | "Suspicious" | "High Risk" | "Dangerous" | "Scam Likely",
  "riskLevel": "Low" | "Medium" | "High" | "Critical",
  "confidence": number, // 0 to 100 percentage
  "executiveSummary": "1-2 short paragraphs in plain English. Reference what competitor checkers (e.g., VirusTotal/ScamAdviser) would report/miss and why our scan is more useful. No technical jargon.",
  "findings": [
    {
      "finding": "Specific structural or language finding name (e.g., 'Competitor Blindspot: Semantic Phishing Urgency Detection')",
      "whyItMatters": "1 short sentence why this matters",
      "impact": "1 short sentence impact",
      "confidence": "High" | "Medium" | "Low"
    }
  ], // Maximum 2 findings
  "positiveSignals": ["positive indicator 1", "positive indicator 2"], // Maximum 2 items
  "negativeSignals": ["negative indicator 1", "negative indicator 2"], // Maximum 2 items
  "scoreBreakdown": [
    { "name": "Factor name", "value": number } // e.g. "Valid SSL Check" -> 10, "New Domain Registration" -> -20. They must add up to the final score from a baseline of 90. Maximum 3 items
  ],
  "redFlags": [
    { "title": "Fake Urgency" | "Suspicious Payment Request" | "OTP Request" | "Crypto Scam Pattern" | "Job Fee Request" | "Gift Card Request", "description": "1 short sentence trigger explanation" }
  ], // Maximum 2 items
  "whatItMeans": [
    { "advice": "Short advice statement", "consequence": "1 short sentence consequence detail" }
  ], // Maximum 2 items
  "matchedPatterns": [
    { "pattern": "Employment Scam / Crypto Scam / Fake Delivery Scam / Tech Support Scam / Investment Scam", "similarity": "1 short sentence explaining pattern match details" }
  ], // Maximum 1 item
  "recommendedActions": [
    { "action": "Action name", "reasoning": "1 short sentence reasoning" }
  ], // Maximum 2 items
  "communityIntel": {
    "reportsCount": number,
    "complaints": ["Short complaint quote 1", "Short complaint quote 2"], // Maximum 2 items
    "trendText": "Spike in activity / stable",
    "trendDirection": "up" | "down" | "stable"
  },
  "simpleExplanation": "1 short sentence explaining this as if talking to a parent with no technical knowledge."
}`;

    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent?key=${apiKey}`;

    // 4. Implement retries and timeout logic
    let attempts = 0;
    const maxAttempts = 2;
    let response: Response | null = null;
    let lastError: Error | null = null;

    while (attempts < maxAttempts) {
      attempts++;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 25000); // 25-second timeout per attempt

      try {
        response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            contents: [{
              parts: [{ text: promptText }]
            }],
            generationConfig: {
              responseMimeType: 'application/json'
            }
          }),
          signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.ok) {
          // Success! Break out of the retry loop.
          break;
        }

        // Check if error is transient (e.g. rate limit, server error) and retry
        if (response.status === 429 || response.status >= 500) {
          console.warn(`Attempt ${attempts} failed with status ${response.status}. Retrying...`);
          // Brief backoff delay (exponential)
          await new Promise(resolve => setTimeout(resolve, attempts * 750));
          continue;
        }

        // Non-transient error (e.g., 400 Bad Request) - fail immediately without retrying
        throw new Error(`Gemini API error status: ${response.status} ${response.statusText}`);
      } catch (err: any) {
        clearTimeout(timeoutId);
        lastError = err;
        console.error(`Attempt ${attempts} error:`, err);
        
        if (err.name === 'AbortError') {
          console.warn(`Attempt ${attempts} timed out after 25 seconds.`);
        }
        
        // Wait before next retry
        await new Promise(resolve => setTimeout(resolve, attempts * 750));
      }
    }

    if (!response || !response.ok) {
      throw lastError || new Error(`Scan request failed after ${maxAttempts} attempts.`);
    }

    const data = await response.json();
    
    if (!data.candidates || data.candidates.length === 0 || !data.candidates[0].content || !data.candidates[0].content.parts[0]) {
      throw new Error('Invalid or empty content candidate returned by Gemini API');
    }

    const rawText = data.candidates[0].content.parts[0].text;
    const resultObj: DetailedAnalysisResult = JSON.parse(rawText);

    // Validate that required fields are present in the response
    if (typeof resultObj.score !== 'number' || !resultObj.verdict || !resultObj.executiveSummary) {
      throw new Error('Returned JSON does not match the DetailedAnalysisResult schema format');
    }

    return new Response(JSON.stringify(resultObj), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (err: any) {
    console.error('Scan API Failure:', err);
    return new Response(
      JSON.stringify({ 
        error: 'Scan analysis failed', 
        details: err.message || err 
      }), 
      {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
};
