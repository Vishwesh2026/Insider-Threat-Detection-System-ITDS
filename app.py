from flask import Flask, request, render_template
from datetime import datetime

import requests
SERVICENOW_USERNAME = "admin"
SERVICENOW_PASSWORD = "Gq=Q25*fqCbV"
SERVICENOW_URL = "https://dev288565.service-now.com/api/now/table/u_insider_threat_data"

def send_to_servicenow(data):
    payload = {
        "u_eventid": data.get("EventID"),      
        "u_eventtime": data.get("EventTime"),
        "u_sourcename": data.get("SourceName"),  
        "u_sourceaddress": data.get("SourceAddress"),
        "u_destinationip": data.get("DestinationIp"),
        "u_connectionstatus": data.get("ConnectionStatus"),
        "u_message": data.get("Message"),
        "u_accessoutcome": data.get("AccessOutcome"),
        "u_eventtype": data.get("event_type")   
        
    }
    response = requests.post(
        SERVICENOW_URL,
        auth=(SERVICENOW_USERNAME, SERVICENOW_PASSWORD),
        headers={"Content-Type": "application/json"},
        json=payload
    )
    return response

app = Flask(__name__)
data_store = []

@app.route('/agent', methods=['POST'])
def receive_data():
    content = request.json
    content['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data_store.append(content)
    servicenow_response = send_to_servicenow(content)
    
    if servicenow_response.status_code in [200, 201]:
        return {"status": "received and sent to ServiceNow"}, 200
    else:
        return {"status": "received but ServiceNow error", "error": servicenow_response.text}, 500

@app.route('/')
def dashboard():
    return render_template('index.html', data=data_store[-50:])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
