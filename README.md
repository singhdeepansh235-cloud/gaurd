
 HEAD
# SentinelFuzz Pro | NCIIPC Security Suite

SentinelFuzz Pro is a next-generation, web-based vulnerability scanner and security assessment platform designed for the NCIIPC. It simulates advanced reconnaissance and fuzzing operations while leveraging Google's Gemini models to generate real-time remediation intelligence and interactive assistance.

## 🚀 Key Features

*   **Live Attack Simulation**: Visualizes the complete lifecycle of a security scan, from Reconnaissance to Fuzzing and Reporting.
*   **AI-Driven Remediation**: Automatically generates detailed remediation reports for detected vulnerabilities using **Gemini 2.5 Flash**. Includes a robust **Offline Mode** with high-fidelity templates when AI services are unavailable.
*   **SentinelBot Assistant**: An integrated AI chatbot powered by **Gemini 3 Pro Preview** that allows operators to ask questions about vulnerabilities, exploits, and security concepts in real-time.
*   **PDF Report Export**: Functional export capability to download detailed vulnerability reports as PDF documents.
*   **Interactive Dashboard**: High-fidelity, cyberpunk-themed dashboard visualizing network traffic, threat distribution, and system health.
*   **Role-Based Access Control**: Secure login system with persistent session management (simulated via local storage).
*   **Contextual Help**: Integrated tooltips and visual guides to assist operators with configuration and analysis.

## 🛠️ Technology Stack

*   **Frontend**: React 19, TypeScript
*   **Styling**: Tailwind CSS (with Typography plugin)
*   **Icons**: Lucide React
*   **Charts**: Recharts
*   **AI Integration**: Google GenAI SDK
    *   *Reporting Engine*: Gemini 2.5 Flash
    *   *Chat Assistant*: Gemini 3 Pro Preview
*   **Reporting Utilities**: jsPDF, html2canvas
*   **State Persistence**: Browser LocalStorage

## 📋 Installation & Setup

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/nciipc/sentinelfuzz-pro.git
    cd sentinelfuzz-pro
    ```

2.  **Install Dependencies**
    ```bash
    npm install
    ```

3.  **Configure API Key**
    Create a `.env` file in the root directory and add your Google Gemini API key:
    ```env
    API_KEY=your_google_ai_studio_key_here
    ```

4.  **Run Application**
    ```bash
    npm start
    ```

## 🎮 Usage Guide

1.  **Authentication**:
    *   Register a new account or log in with existing credentials.
    *   Default Admin (Seeded): `admin@nciipc.gov.in` / `admin123`

2.  **Starting a Scan**:
    *   Navigate to the **Live Scan** tab.
    *   Enter a target URL (e.g., `https://target-system.com`).
    *   Click **Start Scan**.
    *   Watch the live terminal logs and phase stepper as the system enumerates assets and injects payloads.

3.  **Analyzing Reports**:
    *   Once vulnerabilities are detected, go to the **Reports** tab.
    *   Select a vulnerability card to generate an AI remediation strategy.
    *   Click **Export PDF** to download the analysis.
    *   If offline, a template report is generated automatically, which can be regenerated once online.

4.  **AI Assistant**:
    *   Navigate to the **AI Assistant** tab.
    *   Chat with **SentinelBot** to get clarification on findings or general security advice.

## ⚠️ Disclaimer
This tool is a **simulation** designed for educational and demonstration purposes. It does not perform actual malicious attacks on external targets. The "vulnerabilities" detected are simulated for the purpose of testing the reporting and dashboard capabilities.

---
**National Critical Information Infrastructure Protection Centre (NCIIPC)**
=======
#install dependencies

1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`
 797518b03511d5071e7f78b9cb4370341279f268
