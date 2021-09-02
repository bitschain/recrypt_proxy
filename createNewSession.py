from umbral import *
import requests
import sys
import json
import base64

# vistId

alices_secret_key = SecretKey.random()
alices_public_key = alices_secret_key.public_key()

pk_utf = base64.b64encode(bytes(alices_public_key)).decode('utf-8')
sk_utf = base64.b64encode(bytes(alices_secret_key)).decode('utf-8')

payload = {
    'visitId': int(sys.argv[1]),
    'sessionPublicKey': pk_utf
}

response = requests.post('http://167.71.205.128:8000/create_session', data=json.dumps(payload))

if response.status_code == 200:
    print("Session Public Key = " + pk_utf)
    print("Session Secret Key = " + sk_utf)
    print(response.text)
else:
    print(response.json())