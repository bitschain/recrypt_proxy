from umbral import *
import sys
import base64
import json
import requests
from recrypt.views import public_key_from_utf8, secret_key_from_utf8

# VisitId, EmployeeId, Document, Session_Public_Key

PatientPublicKey = public_key_from_utf8(sys.argv[4])
document = sys.argv[3]

payload = {
    'visitId': int(sys.argv[1]),
    'employeeId': int(sys.argv[2]),
    'documents': [
        {
            'document': document,
            'documentType': 1
        }
    ]
}

response = requests.post('http://167.71.205.128:8000/upload_documents', data=json.dumps(payload))

if response.status_code == 200:
    capsule, _ = encrypt(PatientPublicKey, document.encode())
    print("Capsule = " + base64.b64encode(bytes(capsule)).decode('utf-8'))
    print(response.json())
else:
    print(response.json())