import json
import requests
from datetime import datetime, timezone
import google.generativeai as genai

# ========= CONFIGURATION ========= #

GEMINI_API_KEY = "AIzaSyDmKGoyrMhz-VSNWHlXxJQOHYTnB1vgRqM"  # Replace with your actual Gemini API key
# N8N_WEBHOOK_URL = "https://nightmarearch.app.n8n.cloud/webhook-test/threat-detection"  # used when execute workflow is button is triggered  
N8N_WEBHOOK_URL = "https://nightmarearch.app.n8n.cloud/webhook/threat-detection"

genai.configure(api_key=GEMINI_API_KEY)

# ========= ADVANCED SYSTEM PROMPT ========= #

SYSTEM_PROMPT = """
You are a cybersecurity analyst. Given a structured insider threat log, analyze it and classify its severity level and type of threat.

Respond strictly in this JSON format:
{
  "severity": "Critical|High|Medium|Low",
  "threat_category": "string",
  "risk_score": 1-10,
  "recommended_action": "string",
  "explanation": "string"
}

Use the following criteria to assess:

CRITICAL:
- Multiple failed logins from a privileged account (4625)
- Privilege escalation (4672 with SeDebugPrivilege or SeTcbPrivilege)
- Large data transfers (>500MB) over network or USB
- Deletion or tampering of audit logs (1102)
- Suspicious PowerShell usage or encoded commands
- Access to Credential Manager (5379) with multiple results
- Scheduled tasks (4698) or registry mods with `reg.exe`
- Out-of-hours remote logins (LogonType 3 or 10 at 10PM–5AM)

HIGH:
- Access from known malicious IPs
- Unusual command-line tools (net.exe, wscript.exe)
- Use of admin tools by non-admins
- Access to sensitive file paths like /etc/shadow or system32

MEDIUM:
- First-time login from new host
- Logon at unusual hours
- File access to confidential locations without write

LOW:
- Expected logons, common apps, or internal IP access
- Registry reads, metadata views, etc.

Provide detailed explanation and a recommended action for SOC teams.
"""

# ========= SAMPLE LOG (based on Event ID 5379) ========= #

sample_log = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "host": "ashok-anneboina",
    "user_id": "HP",
    "event_id": "5379",
    "event_time": "2025-06-27 01:43:59",
    "source_ip": "192.168.1.5",
    "destination_ip": "192.168.1.100",
    "protocol": "TCP",
    "logon_type": "2",
    "process_name": "Credential Manager",
    "command_line": "Enumerate Credentials",
    "threat_description": "Credential Manager credentials were read.",
    "risk_indicators": ["credential_access", "enumerate_credentials", "audit_success"],
    "source": "nxlog",
    "domain": "ASHOK-ANNEBOINA",
    "target_user": "MicrosoftAccount:user=ashokanneboina@outlook.com",
    "count_of_credentials": 1,
    "process_id": "8392",
    "channel": "Security",
    "message": "Credential Manager access. Enumerate credentials for Microsoft account."
}

# ========= PROMPT BUILDER ========= #

def build_prompt(log):
    return f"""
Analyze the following insider threat event:

Timestamp: {log.get('timestamp')}
Event Time: {log.get('event_time')}
Host: {log.get('host')}
User ID: {log.get('user_id')}
Domain: {log.get('domain')}
Event ID: {log.get('event_id')}
Source IP: {log.get('source_ip')}
Destination IP: {log.get('destination_ip')}
Protocol: {log.get('protocol')}
Logon Type: {log.get('logon_type')}
Process: {log.get('process_name')}
Command Line: {log.get('command_line')}
Target User: {log.get('target_user')}
Credential Count: {log.get('count_of_credentials')}
Message: {log.get('message')}
Indicators: {', '.join(log.get('risk_indicators', []))}
"""

# ========= GEMINI ANALYSIS ========= #

def analyze_log(log):
    model = genai.GenerativeModel("gemini-2.0-flash")
    prompt = build_prompt(log)
    full_prompt = SYSTEM_PROMPT.strip() + "\n\n" + prompt.strip()

    try:
        response = model.generate_content(full_prompt)
        result_text = response.text.strip()

        # DEBUG: Uncomment to see the raw LLM response
        # print("Raw Gemini Response:", result_text)

        analysis = json.loads(result_text)

        return {
            **log,
            **analysis,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        return {
            **log,
            "severity": "Medium",
            "threat_category": "Unknown",
            "risk_score": 5,
            "recommended_action": "Manual review required",
            "explanation": "Gemini response could not be parsed or did not match JSON structure.",
            "error": str(e),
            "analysis_timestamp": datetime.now(timezone.utc).isoformat()
        }

# ========= TRIGGER N8N WEBHOOK ========= #

def send_to_n8n(data):
    try:
        response = requests.post(N8N_WEBHOOK_URL, json=data, timeout=10)
        print(f"✅ Webhook sent: {response.status_code}")
        print(response.text)
    except Exception as e:
        print(f"❌ Failed to send to n8n: {e}")

# ========= MAIN EXECUTION ========= #

def main():
    print("🚀 Detecting Insider Threat...")

    log_data = sample_log

    print("🧠 Running Gemini analysis...")
    enriched = analyze_log(log_data)

    print(f"🔍 Severity: {enriched['severity']} | Category: {enriched['threat_category']}")

    if enriched["severity"] in ["Medium", "High", "Critical"]:
        print("📡 Sending to n8n for alert automation...")
        send_to_n8n(enriched)
    else:
        print("✅ Low severity, no action taken.")

    print("\n📝 Final Analysis:")
    print(json.dumps(enriched, indent=2))


if __name__ == "__main__":
    main()
