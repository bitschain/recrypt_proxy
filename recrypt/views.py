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
hospital_public_key_utf8_from_id = {"2":'A+1gwwUvBWMbrhb7YmoCITwXUg7KjfFIbgRhD60jct6l'}


def call_for_document(hospital_id_from_endpoint,report_id_from):
    if hospital_server_working:
        r = requests.post(hospital_id_from_endpoint+"/get_documents", params=report_id_from)
        if r.status_code == 200:
            return r.json()
    else:
        capsule = "AgoYwzrl9qVJcyhU78zdEWvMwaL89J9N/M3xHdVGw5WnArFI6vWuut6yFaxGWon1cs3NDXUhuxD+8OxjxYOiqzXVRraBPjgwWKUrsOHGwDXhAVNQhL69XxAKEsiJ212D/QM="
        encrypted_document = "7ntX0CMybx8l72EAE+zjm9d5o4l2/Ly6ASbK1eo5zH4U2BIambovwAWed+VkM0kP5XfbGmDsUnjjlIt22ULUK0BIyIA="
        return [(capsule,encrypted_document)]

'''
curl --request POST \
  --url http://127.0.0.1:8001/transfer_doc_request \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data hospital_id_from=1 \
  --data report_ids=1 \
  --data hospital_id_to=2 \
  --data 're_encryption_key_list=AjhGghgbLoGWnEoCPQFR6PHotC0j+bFyT1MVXF2SGEsMAvCKyd6Zs20N7+9duLM4X3YztVJN1kEbQ2+lceFlCuJ9oYK8Rw5kP/ngFmkzpGquLO7eHlO3P5MIegasuiE5HSoDEEX4Q7eiH62UOF4r78l6tw05tD5hO0porfjNZdNSUIkCwLoPO3KX2oKP2LMmztXVhGDSt1fx6XaopBC9xq9eEHkDSndGwYAlbBnvB/1D4XrhILDmrC+IpunqRhTgRtuWH/MDtzTeO9f83h7U+AQ1mPH8nEQAPRGrOKVY/OIxs0eZEp4CzyAz+z7jPx0wxk2pF4NXvkPWV8C7xecb9jMpgCF7pSi/UMEwLWu8P5tN/hgK5CWEr/uKgKwGERwlb1cKQB0cL+4cuyqxAFotxucGd0eg3PVaz4JAzRk3d2RSsqs5zOdsf/24eyaFS1AdjsrlOR7JyfuLEX4oFJXPWgWqK2VRu7c=' \
  --data 'patient_session_public_key_utf8=Ag7HVBkG8th5d+nIcRsVmhZtHpU3aCba/k346y4hOKSu' \
  --data patient_session_verifying_key_utf8=fdvasd
'''

@csrf_exempt
def patient_request(request):
    if request.method == 'POST':
        hospital_id_from=request.POST['hospital_id_from']
        hospital_id_from_endpoint = hospital_url_from_id[hospital_id_from]
        report_id_from = request.POST.getlist('report_ids')
        hospital_id_to= request.POST['hospital_id_to']
        kfrag_of_1_list = request.POST.getlist('re_encryption_key_list')
        patient_session_public_key_utf8 = request.POST.getlist('patient_session_public_key_utf8')
        patient_session_public_key = PublicKey.from_bytes(base64.b64decode(patient_session_public_key_utf8.encode('utf-8')))
        patient_session_verifying_key_utf8 = request.POST.getlist('patient_session_verifying_key_utf8')
        patient_session_verifying_key = PublicKey.from_bytes(base64.b64decode(patient_session_verifying_key_utf8.encode('utf-8')))
        encrypted_documents_received = call_for_document(hospital_id_from_endpoint,report_id_from)
        # if encrypted_documents_received:
        #     return HttpResponse(encrypted_documents_received)

        receiving_hospital_public_key_utf8 = hospital_public_key_utf8_from_id[hospital_id_to]
        receiving_hospital_public_key = PublicKey.from_bytes(base64.b64decode(receiving_hospital_public_key_utf8.encode('utf-8')))

        cfrags = list()  # Bob's cfrag collection
        # Several Ursulas perform re-encryption, and Bob collects the resulting `cfrags`.
        for i,encrypted_document in enumerate(encrypted_documents_received):
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
        print(cfrags)
        return HttpResponse("Done")

def hospital_from(request):
    pass

def hospital_to():
    # send a post request to hosbital_b
    pass