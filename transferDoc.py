import requests
from umbral import *
import sys
import base64
from recrypt.views import public_key_from_utf8, secret_key_from_utf8

# Capsule, Patient_session_secret_key, ReportId, HospitalBVisitId

HOSPITAL_A_PUBLIC_KEY = public_key_from_utf8("AhU74FcV3aaKsqM2lpoe1Z+x6W1V/4IO+0hPqhxqJd9l")
HOSPITAL_A_PRIVATE_KEY = secret_key_from_utf8("EJpef16rRYgrCvxXjXgKq8RC+awGIFsXlRLZfQHsBJ8=")
HOSPITAL_B_PUBLIC_KEY = public_key_from_utf8("AwcMA3b8cTqpW8Rv5oy38tU/K7wVeMbEUTYFmtzW6tly")
HOSPITAL_B_PRIVATE_KEY = secret_key_from_utf8("IjsIeHm0Glr4WRt5Pm79rM94/O7LLhghUAqGJg5wokY=")

PatientPrivateKey = secret_key_from_utf8(sys.argv[2])

SIGNING_KEY = SecretKey.random()
SIGNER = Signer(SIGNING_KEY)
VERIFYING_KEY = SIGNING_KEY.public_key()

alices_verifying_key_utf8 = base64.b64encode(bytes(VERIFYING_KEY)).decode('utf-8')
capsule = Capsule._from_exact_bytes(data = base64.b64decode(sys.argv[1].encode('utf-8')))

kfrags = generate_kfrags(delegating_sk=PatientPrivateKey,
                         receiving_pk=HOSPITAL_B_PUBLIC_KEY,
                         signer=SIGNER,
                         threshold=1,
                         num_kfrags=1)

re_encryption_key = base64.b64encode(bytes(kfrags[0])).decode('utf-8')

print("Verifying Key = " + alices_verifying_key_utf8)
print("ReEncryption Key list = " + re_encryption_key)

payload = {
    'hospital_id_from': 1,
    'hospital_id_to': 2,
    'report_ids': int(sys.argv[3]),
    'patient_session_verifying_key_utf8': alices_verifying_key_utf8,
    're_encryption_key_list': re_encryption_key,
    'patient_session_public_key_utf8': base64.b64encode(bytes(PatientPrivateKey.public_key())).decode('utf-8'),
    'hospital_to_visit_id': int(sys.argv[4])
}

response = requests.post('http://167.71.205.128:8007/transfer_doc_request', payload)
print(response.text)
