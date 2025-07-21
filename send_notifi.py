
import json
import requests
from datetime import datetime, timezone
import google.generativeai as genai
import time

# ========== CONFIGURATION ========== #

GEMINI_API_KEY = "AIzaSyDmKGoyrMhz-VSNWHlXxJQOHYTnB1vgRqM"
N8N_WEBHOOK_URL = "https://nightmarearch.app.n8n.cloud/webhook/threat-detection"

SERVICENOW_INSTANCE = "https://dev288565.service-now.com"
SERVICENOW_TABLE = "u_insider_threat_data"
SERVICENOW_USERNAME = "admin"
SERVICENOW_PASSWORD = "Gq=Q25*fqCbV"
SERVICENOW_API_URL = f"{SERVICENOW_INSTANCE}/api/now/table/{SERVICENOW_TABLE}"

genai.configure(api_key=GEMINI_API_KEY)

# ========== SYSTEM PROMPT ========== #

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
- Scheduled tasks (4698) or registry mods with reg.exe
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

# ========== SERVICE NOW FETCH ========= #

def fetch_logs_from_servicenow(limit=10):
    try:
        response = requests.get(
            SERVICENOW_API_URL,
            auth=(SERVICENOW_USERNAME, SERVICENOW_PASSWORD),
            headers={"Accept": "application/json"},
            params={"sysparm_limit": limit, "sysparm_query": "u_processed=false"}
        )
        response.raise_for_status()
        return response.json().get("result", [])
    except Exception as e:
        print(f"[❌] Error fetching logs from ServiceNow: {e}")
        return []

# ========== PROMPT BUILDER ========= #

def build_prompt(log):
    return f"""
Analyze the following insider threat event:

Timestamp: {log.get('u_timestamp')}
User ID: {log.get('u_userid')}
Machine Name: {log.get('u_machinename')}
Logon Type: {log.get('u_logontype')}
Auth Result: {log.get('u_authresult')}
MFA Used: {log.get('u_mfaused')}
Logon Source: {log.get('u_logonsource')}
Session ID: {log.get('u_sessionid')}
"""

# ========== ANALYZE USING GEMINI ========= #

def analyze_log(log):
    model = genai.GenerativeModel("gemini-2.0-flash")
    full_prompt = SYSTEM_PROMPT.strip() + "\n\n" + build_prompt(log).strip()
    try:
        response = model.generate_content(full_prompt)
        analysis = json.loads(response.text.strip())
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
            "explanation": "Gemini response could not be parsed.",
            "error": str(e),
            "analysis_timestamp": datetime.now(timezone.utc).isoformat()
        }

# ========== SEND TO N8N ========= #

def send_to_n8n(log):
    try:
        res = requests.post(N8N_WEBHOOK_URL, json=log, timeout=10)
        print(f"✅ Sent to n8n | Status: {res.status_code}")
    except Exception as e:
        print(f"❌ Failed to send to n8n: {e}")

# ========== MARK LOG AS PROCESSED ========= #

def mark_log_processed(sys_id, enriched):
    try:
        update_data = {
            "u_processed": "true",
            "u_processed_time": enriched["analysis_timestamp"],
            "u_severity": enriched["severity"],
            "u_risk_score": enriched["risk_score"],
            "u_threat_category": enriched["threat_category"],
            "u_explanation": enriched["explanation"]
        }
        response = requests.patch(
            f"{SERVICENOW_API_URL}/{sys_id}",
            auth=(SERVICENOW_USERNAME, SERVICENOW_PASSWORD),
            headers={"Content-Type": "application/json"},
            json=update_data,
            timeout=10
        )
        print(f"☑️ Log {sys_id} marked as processed.")
    except Exception as e:
        print(f"❌ Failed to update ServiceNow record {sys_id}: {e}")

# ========== MAIN EXECUTION LOOP ========= #

def main():
    print("🚀 Fetching logs from ServiceNow...")
    logs = fetch_logs_from_servicenow()

    if not logs:
        print("🔍 No new logs found.")
        return

    for log in logs:
        sys_id = log.get("sys_id")
        print(f"\n🧠 Analyzing log: {sys_id}")
        enriched = analyze_log(log)

        # print(f"🔍 Severity: {enriched['severity']} | Category: {enriched['threat_category']}")
        if enriched["severity"] in ["Medium", "High", "Critical"]:
            send_to_n8n(enriched)

        mark_log_processed(sys_id, enriched)

if __name__ == "__main__":
    while True:
        main()
        time.sleep(30)  # Poll every 30 seconds (adjust as needed)
