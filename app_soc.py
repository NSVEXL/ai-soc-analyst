import streamlit as st
import os
import requests
from crewai import Agent, Task, Crew
from langchain_google_genai import ChatGoogleGenerativeAI
from crewai.tools import tool

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="AI SOC Analyst", page_icon="🛡️")
st.title("🛡️ AI Cyber Security Analyst")
st.markdown("Automated IP Investigation using Gemini & VirusTotal")

# --- SIDEBAR: Configuration and Inputs ---
with st.sidebar:
    st.header("Settings")
    # Using password type for security to mask API keys
    google_key = st.text_input("Google API Key", type="password")
    vt_key = st.text_input("VirusTotal API Key", type="password")
    ip_to_check = st.text_input("IP Address to investigate", placeholder="8.8.8.8")

# --- CORE LOGIC AND AGENT EXECUTION ---
if st.button("Start Investigation") and google_key and vt_key and ip_to_check:
    
    # Set the environment variable for the Google API
    os.environ["GOOGLE_API_KEY"] = google_key

    # Initialize the LLM (The Brain)
    gemini_llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash", 
        temperature=0.2
    )

    # Define the custom tool for VirusTotal API (The Hand)
    @tool("IP_Reputation_Tool")
    def ip_reputation_tool(ip: str) -> str:
        """Checks an IP address on VirusTotal and returns detection stats."""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"accept": "application/json", "x-apikey": vt_key}
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                return f"IP: {ip} | Malicious Detections: {stats['malicious']}"
            return f"Error: Received status code {response.status_code}"
        except Exception as e:
            return f"Connection Error: {str(e)}"

    # Define the SOC Analyst Agent (The Mind)
    soc_analyst = Agent(
        role='Senior SOC Analyst',
        goal='Analyze IP reputation and provide clear security recommendations.',
        backstory="""You are a high-level cybersecurity expert. You analyze 
        reputation data and decide if an IP poses a threat to the network.""",
        tools=[ip_reputation_tool],
        llm=gemini_llm
    )

    # Define the Mission (The Task)
    investigation_task = Task(
        description=f"Investigate the IP {ip_to_check} and provide a verdict on whether to block it.",
        expected_output="A concise technical report including a risk score and recommendation.",
        agent=soc_analyst
    )

    # Visual feedback for the user while the agent is working
    with st.status("Analyst is investigating the threat...", expanded=True) as status:
        crew = Crew(agents=[soc_analyst], tasks=[investigation_task])
        result = crew.kickoff()
        status.update(label="Investigation Complete!", state="complete", expanded=False)

    # Display the final report in the main area
    st.subheader("Final Security Report")
    st.write(result.raw)

else:
    # Instructions for the user if inputs are missing
    st.info("Please enter your API keys and the target IP in the sidebar, then click 'Start Investigation'.")