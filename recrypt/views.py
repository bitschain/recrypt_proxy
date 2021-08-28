import base64

from django.http import HttpResponse
from django.shortcuts import render

# Create your views here.
import requests
from django.views.decorators.csrf import csrf_exempt
from umbral import reencrypt, KeyFrag, CapsuleFrag, PublicKey

hospital_server_working = False

## Below will be received from some globally consistent authority like the NMDH
hospital_url_from_id = {"1":"http://127.0.0.1:8000/"}
hospital_public_key_utf8_from_id = {"2":'A8IvGJYDfh3iWBaQI1VYoficf8H7fS+78GyNo4h0DTMs'}


def utf8_to_public_key(utf8_string: str) -> 'PublicKey':
    return PublicKey.from_bytes(base64.b64decode(utf8_string.encode('utf-8')))


def call_for_document(hospital_id_from_endpoint,report_id_from):
    if hospital_server_working:
        r = requests.post(hospital_id_from_endpoint+"/get_documents", params=report_id_from)
        if r.status_code == 200:
            return r.json() ##TODO
    else:
        capsule = 'AlSAnZC2EPgNId5lOVuF6Cj3MnAxBkcoDWN3MgSyzNY4Ak6GlJWhkuRjGepM1u7K5iGtswjzmq297e6k5bZQE4XKrfrO+l4mLsZAoN1Q4qWYoWyecXcygzb2BP+EImWtdrs='
        encrypted_document = 'aMjvtum024t43NYb4P7ttpJYXNCjUkqVHnty+CYkwYUEY2KEvA8sDO9U5lXqWVr0THedaTZLmeR5XHdqBfhT3a4cHsk='
        return [(capsule,encrypted_document)]


'''
curl --request POST \
  --url http://127.0.0.1:8001/transfer_doc_request \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data hospital_id_from=1 \
  --data report_ids=1 \
  --data hospital_id_to=2 \
  --data 're_encryption_key_list=+dygxIgpgjYJLwAtSZipp58kD4eN9yAfE1yOd3XCtXaOXFVpoRU2w0m4olSI+nQ/s4FIuCzIKMqYM30grd34GwNR7KI4t+VYpe3bE8nRWT4wGouR3/hBvgUUpQqyqApHXAPvPnyTeEzoJneiCLLaYzIhD+li7Qjxqub90MWIWFEpr2FSi9p60Rh1kT1MlAmXvXuQZTxZRU5lgzQok6XuLG3TTapTHacyZ0Hy0WSn7ie+Kxr0pfRMyaKGBRVepLe7YMgIJm3QeNrzmusx6YFqHymmzgu3UFUuXXGQJrUe9aB8MUdinYCvsuel5GXFU3EO0GqYOSMqZS4tdOcdUfszJCP2AQE=' \
  --data patient_session_public_key_utf8=A2m/wR3h8uvM/7efAGD2JisUuMgiYD2ZNj5UHcpYKQ2v \
  --data patient_session_verifying_key_utf8=A5rAUfrl2H74YWpv04lL386Hgq1cdFgDnFagZ77LpUR0

'''


@csrf_exempt
def patient_request(request):
    if request.method == 'POST':
        hospital_id_from=request.POST['hospital_id_from']
        hospital_id_from_endpoint = hospital_url_from_id[hospital_id_from]
        report_id_from = request.POST.getlist('report_ids')
        hospital_id_to= request.POST['hospital_id_to']
        kfrag_of_1_list = request.POST.getlist('re_encryption_key_list')
        patient_session_public_key_list_utf8 = request.POST.getlist('patient_session_public_key_utf8')
        patient_session_verifying_key_list_utf8 = request.POST.getlist('patient_session_verifying_key_utf8')
        encrypted_documents_received = call_for_document(hospital_id_from_endpoint,report_id_from)
        # if encrypted_documents_received:
        #     return HttpResponse(encrypted_documents_received)

        receiving_hospital_public_key_utf8 = hospital_public_key_utf8_from_id[hospital_id_to]
        receiving_hospital_public_key = utf8_to_public_key(receiving_hospital_public_key_utf8)

        cfrags = list()  # Bob's cfrag collection
        # Several Ursulas perform re-encryption, and Bob collects the resulting `cfrags`.
        for i,encrypted_document in enumerate(encrypted_documents_received):
            patient_session_public_key = utf8_to_public_key(patient_session_public_key_list_utf8[i])
            patient_session_verifying_key = utf8_to_public_key(patient_session_verifying_key_list_utf8[i])

            kfrag_bytes = base64.b64decode(kfrag_of_1_list[i].encode('utf-8'))
            new_kfrag = KeyFrag.from_bytes(kfrag_bytes)
            new_kfrag = new_kfrag.verify(verifying_pk=patient_session_verifying_key,
                                         delegating_pk=patient_session_public_key,
                                         receiving_pk=receiving_hospital_public_key)

            capsule_bytes = base64.b64decode(encrypted_document[0].encode('utf-8'))
            new_capsule = CapsuleFrag.from_bytes(capsule_bytes)
            new_capsule = new_capsule.verify(verifying_pk=patient_session_verifying_key,
                                         delegating_pk=patient_session_public_key,
                                         receiving_pk=receiving_hospital_public_key)

            cfrag = reencrypt(capsule=new_capsule, kfrag=new_kfrag)
            cfrag_deserialized = base64.b64encode(bytes(cfrag)).decode('utf-8')
            cfrags.append(cfrag)  # Bob collects a cfrag
        print(cfrag_deserialized)
        return HttpResponse("Done")

def hospital_from(request):
    pass

def hospital_to():
    # send a post request to hosbital_b
    pass