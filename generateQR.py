import requests
import sys
import json

# patientId employeeId

print(sys.argv[1])
print(sys.argv[2])

payload = {
    'patientId': (sys.argv[1]),
    'employeeId': (sys.argv[2])
}

response = requests.post('http://167.71.205.128:8000/generate_qr_string', data=json.dumps(payload))

if response.status_code == 200:
    print(response.json())
else:
    print(response)