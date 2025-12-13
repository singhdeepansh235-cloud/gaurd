<<<<<<< HEAD

=======
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
import { GoogleGenAI } from "@google/genai";
import { Vulnerability } from "../types";

const apiKey = process.env.API_KEY || '';
<<<<<<< HEAD
const ai = apiKey ? new GoogleGenAI({ apiKey }) : null;

const wait = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

const generateFallbackReport = (vuln: Vulnerability, reason: string): string => {
  const vTitle = vuln.title.toLowerCase();
  let remediation = "Implement strict input validation on all user-supplied data. Ensure least privilege principles are applied to database and system access.";
  let codeFix = "// Generic Input Validation\nif (!isValid(userInput)) {\n  throw new Error('Invalid Input');\n}";

  if (vTitle.includes('sql')) {
    remediation = "Use Parameterized Queries (Prepared Statements) for all database interactions. Do not concatenate user input directly into SQL strings. Ensure that the database user has the minimum necessary privileges.";
    codeFix = "const query = 'SELECT * FROM users WHERE id = $1';\n// Secure execution using prepared statements\nawait client.query(query, [userInput]);";
  } else if (vTitle.includes('xss')) {
    remediation = "Contextually encode all output data before rendering it in the browser. Implement a Content Security Policy (CSP) to restrict sources of executable scripts.";
    codeFix = "// Encode before rendering\nconst cleanInput = DOMPurify.sanitize(userInput);\ndocument.getElementById('output').textContent = cleanInput;";
  } else if (vTitle.includes('rce') || vTitle.includes('remote code')) {
    remediation = "Avoid using functions that execute system commands (e.g., `eval`, `exec`). If necessary, use allow-lists for inputs and run in a sandboxed environment with restricted permissions.";
    codeFix = "// Bad: exec('ping ' + input)\n\n// Good: Use specific libraries or predefined commands\nconst allowedCommands = ['ping', 'traceroute'];\nif (allowedCommands.includes(cmd)) {\n  spawn(cmd, [safeArg]);\n}";
  } else if (vTitle.includes('idor')) {
    remediation = "Implement proper access control checks on every object reference. Verify that the authenticated user is authorized to access the requested resource ID.";
    codeFix = "// Check ownership before returning resource\nconst resource = await db.getResource(id);\nif (resource.ownerId !== session.userId) {\n  throw new Error('Unauthorized');\n}";
  }

  return `
# Vulnerability Analysis (Offline Mode)

> **System Notification:** ${reason}. A high-fidelity template report has been generated to provide immediate guidance.

## 1. Executive Summary
A **${vuln.title}** vulnerability was detected at endpoint \`${vuln.endpoint}\`. This issue is classified as **${vuln.severity}**. It poses a significant risk to the application's integrity and requires immediate attention to prevent exploitation.

## 2. Technical Findings
**Payload:**
\`\`\`
${vuln.payload}
\`\`\`
**Observation:**
The application accepted the malformed input without proper rejection or sanitization, indicating a failure in the input handling logic or access control mechanisms.

## 3. Impact Assessment
*   **Confidentiality:** Potential unauthorized access to sensitive user data or system configurations.
*   **Integrity:** Possible modification of database records, file systems, or transaction data.
*   **Availability:** Risk of service disruption, denial of service, or resource exhaustion.

## 4. Remediation Strategy
${remediation}

## 5. Secure Implementation
\`\`\`javascript
${codeFix}
\`\`\`
  `;
};

export const generateRemediationReport = async (vuln: Vulnerability): Promise<string> => {
  // Immediate fallback if no key
  if (!apiKey || !ai) {
    return generateFallbackReport(vuln, "API Key is not configured");
  }

  const prompt = `
    You are a Senior Application Security Engineer for NCIIPC.
    Analyze the following detected vulnerability and provide a remediation report.
    
    **Vulnerability Details:**
    - Title: ${vuln.title}
    - Endpoint: ${vuln.endpoint}
    - Payload Used: \`${vuln.payload}\`
    - Severity: ${vuln.severity}
    
    **Required Output Format (Markdown):**
    1. **Executive Summary**: Brief explanation of the risk.
    2. **Technical Analysis**: How the attack works based on the payload.
    3. **Impact Assessment**: What could happen if exploited.
    4. **Remediation Strategy**: Concrete steps to fix it.
    5. **Code Fix Example**: Provide a generic code snippet (in Python, Go, or JS) showing a secure implementation.
  `;

  let retries = 0;
  const maxRetries = 2; // 3 attempts total

  while (retries <= maxRetries) {
    try {
      const response = await ai!.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: [{
          role: 'user',
          parts: [{ text: prompt }]
        }],
      });

      if (response.text) {
        return response.text;
      } else {
        throw new Error("Empty response from AI model.");
      }
    } catch (error: any) {
      console.warn(`Attempt ${retries + 1} failed:`, error.message);

      const isQuota = error.toString().includes('429') || error.toString().includes('Quota') || error.toString().includes('403');
      const isServer = error.toString().includes('500') || error.toString().includes('503');

      // If we have retries left and it's a transient error (Quota or Server)
      if ((isQuota || isServer) && retries < maxRetries) {
        retries++;
        const backoffTime = Math.pow(2, retries) * 1000 + Math.random() * 500; // Exponential backoff + jitter
        console.log(`Retrying in ${Math.round(backoffTime)}ms...`);
        await wait(backoffTime);
        continue;
      }

      // If we are out of retries or it's a fatal error, return fallback
      if (isQuota) {
        return generateFallbackReport(vuln, "AI Service Quota Exceeded");
      }

      return generateFallbackReport(vuln, `AI Service Unavailable (${error.message || 'Unknown Error'})`);
    }
  }

  return generateFallbackReport(vuln, "Maximum retries exceeded");
};

export const analyzeTargetSurface = async (target: string, subdomains: string[]): Promise<string> => {
  if (!apiKey || !ai) return "API Key Missing";
=======
const ai = new GoogleGenAI({ apiKey });

export const generateRemediationReport = async (vuln: Vulnerability): Promise<string> => {
  if (!apiKey) {
    return "## Error\nAPI Key not configured. Please set process.env.API_KEY.";
  }

  try {
    const prompt = `
      You are a Senior Application Security Engineer for NCIIPC.
      Analyze the following detected vulnerability and provide a remediation report.
      
      **Vulnerability Details:**
      - Title: ${vuln.title}
      - Endpoint: ${vuln.endpoint}
      - Payload Used: \`${vuln.payload}\`
      - Severity: ${vuln.severity}
      
      **Required Output Format (Markdown):**
      1. **Executive Summary**: Brief explanation of the risk.
      2. **Technical Analysis**: How the attack works based on the payload.
      3. **Impact Assessment**: What could happen if exploited.
      4. **Remediation Strategy**: Concrete steps to fix it.
      5. **Code Fix Example**: Provide a generic code snippet (in Python, Go, or JS) showing a secure implementation.
    `;

    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
      config: {
        systemInstruction: "You are a strict cybersecurity auditing system. Output clean, professional Markdown.",
      }
    });

    return response.text || "No report generated.";
  } catch (error) {
    console.error("Gemini API Error:", error);
    return "## Error Generating Report\nFailed to contact AI analysis engine. Please check your connection or API limits.";
  }
};

export const analyzeTargetSurface = async (target: string, subdomains: string[]): Promise<string> => {
  if (!apiKey) return "API Key Missing";
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268

  const prompt = `
    Target: ${target}
    Discovered Assets: ${subdomains.join(', ')}
    
    Provide a brief "Attack Surface Assessment" summarizing the potential risks based on these exposed subdomains. Keep it under 150 words.
  `;

  try {
<<<<<<< HEAD
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: [{
        role: 'user',
        parts: [{ text: prompt }]
      }],
=======
     const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
    });
    return response.text || "Analysis failed.";
  } catch (e) {
    return "Analysis unavailable.";
  }
<<<<<<< HEAD
};

export const createChatSession = () => {
  if (!apiKey || !ai) return null;

  try {
    return ai.chats.create({
      model: 'gemini-2.5-flash',
    });
  } catch (error) {
    console.error('Failed to create chat session:', error);
    return null;
  }
};
=======
}
>>>>>>> 797518b03511d5071e7f78b9cb4370341279f268
