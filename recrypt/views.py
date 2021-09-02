import base64

from django.http import HttpResponse, JsonResponse
#remove HttpResponse,JsonResponse if not needed when going to production
from django.shortcuts import render

# Create your views here.
import requests
from django.views.decorators.csrf import csrf_exempt
from umbral import reencrypt, KeyFrag, CapsuleFrag, PublicKey, Capsule, decrypt_reencrypted, SecretKey
#Remove CapsuleFrag, decrypt_reencrypted, SecretKey in production

hospital_server_working = True

## Below will be received from some globally consistent authority like the NMDH
hospital_url_from_id = {"1":"http://167.71.205.128:8000", "2":"http://167.71.205.128:8001"}
hospital_public_key_utf8_from_id = {"1":'AhU74FcV3aaKsqM2lpoe1Z+x6W1V/4IO+0hPqhxqJd9l',"2":'AwcMA3b8cTqpW8Rv5oy38tU/K7wVeMbEUTYFmtzW6tly'}


def public_key_from_utf8(utf8_string: str) -> 'PublicKey':
    return PublicKey.from_bytes(base64.b64decode(utf8_string.encode('utf-8')))


## Remove later
def secret_key_from_utf8(utf8_string: str) -> 'SecretKey':
    return SecretKey.from_bytes(base64.b64decode(utf8_string.encode('utf-8')))


def utf8_from_object(some_umbral_object) -> str:
    return base64.b64encode(bytes(some_umbral_object)).decode('utf-8')


def call_for_document(hospital_id_from_endpoint,report_id_from):
    payload = {'report_ids': report_id_from}
    r = requests.get(hospital_id_from_endpoint+"/get_documents", params=payload)
    if r.status_code == 200:
        body = r.json()
        reports = []
        for document in body['result']:
            # print(document)
            capsule = document['capsule']
            encrypted_document = document['encrypted_document']
            report_id = document['report_id']
            document_tuple = (capsule, encrypted_document, report_id)
            reports.append(document_tuple)
        # return r.json() ##TODO
        # print(reports)
        return reports
    elif r.status_code == 404:
        return r


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
        hospital_to_visit_id = request.POST['hospital_to_visit_id']
        kfrag_of_1_list = request.POST.getlist('re_encryption_key_list')
        patient_session_public_key_list_utf8 = request.POST.getlist('patient_session_public_key_utf8')
        patient_session_verifying_key_list_utf8 = request.POST.getlist('patient_session_verifying_key_utf8')
        encrypted_documents_received = call_for_document(hospital_id_from_endpoint,report_id_from)
        # if encrypted_documents_received:
        #     return HttpResponse(encrypted_documents_received)

        receiving_hospital_public_key_utf8 = hospital_public_key_utf8_from_id[hospital_id_to]
        receiving_hospital_public_key = public_key_from_utf8(receiving_hospital_public_key_utf8)
        dicionary_of_documents = {'hospital_to_visit_id': hospital_to_visit_id}
        cfrags = list()  # Bob's cfrag collection
        # Several Ursulas perform re-encryption, and Bob collects the resulting `cfrags`.
        for i,encrypted_document in enumerate(encrypted_documents_received):
            patient_session_public_key = public_key_from_utf8(patient_session_public_key_list_utf8[i])
            patient_session_verifying_key = public_key_from_utf8(patient_session_verifying_key_list_utf8[i])

            kfrag_bytes = base64.b64decode(kfrag_of_1_list[i].encode('utf-8'))
            new_kfrag = KeyFrag.from_bytes(kfrag_bytes)
            new_kfrag = new_kfrag.verify(verifying_pk=patient_session_verifying_key,
                                         delegating_pk=patient_session_public_key,
                                         receiving_pk=receiving_hospital_public_key)

            capsule_bytes = base64.b64decode(encrypted_document[0].encode('utf-8'))
            new_capsule = Capsule.from_bytes(capsule_bytes)
            # new_capsule = new_capsule.verify(verifying_pk=patient_session_verifying_key,
            #                              delegating_pk=patient_session_public_key,
            #                              receiving_pk=receiving_hospital_public_key)

            cfrag = reencrypt(capsule=new_capsule, kfrag=new_kfrag)
            cfrag_deserialized = base64.b64encode(bytes(cfrag)).decode('utf-8')
            cfrags.append(cfrag_deserialized)  # Bob collects a cfrag

            report_dict = {'hospital_report_unique_key': hospital_id_to+"_"+encrypted_document[2], 'report_id': encrypted_document[2], 'ciphertext': encrypted_document[1],
                           'capsule': encrypted_document[0],
                           'patient_session_public_key': patient_session_public_key_list_utf8[i],
                           'patient_session_verifying_key': patient_session_verifying_key_list_utf8[i],
                           'cfrag': cfrag_deserialized}
            dicionary_of_documents.setdefault('reports',[]).append(report_dict)

        all_document_details = zip(report_id_from,patient_session_public_key_list_utf8,encrypted_documents_received, cfrags)

        # create a dictionary
        document_dictionary = {}
        # return JsonResponse(dicionary_of_documents)
        r = hospital_to(hospital_id_to,dicionary_of_documents)
        if r.status_code == 200:
            return HttpResponse('Successful Transfer of documents')
        else:
            return HttpResponse('Failure')

def hospital_from(request):
    pass

def hospital_to(hospital_id_to, dicionary_of_documents):
    # send a post request to hosbital_b
    hospital_id_to_endpoint = hospital_url_from_id[hospital_id_to]
    r = requests.post(hospital_id_to_endpoint+"/add_documents", json = dicionary_of_documents) # , all_document_details
    return r
