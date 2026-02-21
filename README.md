# 🛡️ AI SOC Analyst Tool
**Automated Threat Intelligence & IP Reputation Checker**

An interactive, AI-driven cybersecurity tool designed to automate the initial triage of suspicious IP addresses. Built with Python and Streamlit, this tool integrates the reasoning capabilities of Large Language Models (LLMs) with real-world threat intelligence databases to assist Security Operations Center (SOC) analysts in rapid decision-making.

By automating repetitive OSINT and reputation checks, this tool bridges the gap between raw data and actionable security intelligence, reflecting a proactive approach to defense.

## 🚀 Features
* **Automated Threat Intelligence:** Connects directly to the **VirusTotal API** to retrieve real-time malicious detection scores for any target IP.
* **AI-Powered Triage:** Utilizes **CrewAI** and **Google Gemini (2.5 Flash)** to analyze the retrieved data and generate a clear, professional security recommendation (e.g., Block, Monitor, or Safe).
* **Interactive UI:** Built with **Streamlit** to provide a clean, user-friendly web interface, allowing analysts to input data and receive reports without interacting with the command line.

## 🛠️ Technologies Used
* **Python 3.11** * **CrewAI** (Agentic AI Framework)
* **Google Gemini API** (LLM Reasoning)
* **VirusTotal API** (Threat Intelligence)
* **Streamlit** (Web Frontend)

## 📋 Prerequisites
To run this tool locally, you will need:
* Python 3.11 or higher
* A free [Google AI Studio API Key](https://aistudio.google.com/app/apikey)
* A free [VirusTotal API Key](https://www.virustotal.com/gui/user/username/apikey)

## 💻 Installation & Usage

**1. Clone the repository:**
```bash
git clone [https://github.com/YOUR_USERNAME/ai-soc-analyst.git](https://github.com/YOUR_USERNAME/ai-soc-analyst.git)
cd ai-soc-analyst