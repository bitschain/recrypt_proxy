from django.http import HttpResponse
from django.shortcuts import render

# Create your views here.
import requests
from django.views.decorators.csrf import csrf_exempt

hospital_server_working = False

def call_for_document(hospital_id_from_endpoint,report_id_from):
    if hospital_server_working:
        r = requests.post(hospital_id_from_endpoint+"/get_documents", params=report_id_from)
        if r.status_code == 200:
            return True
    else:
        return True

@csrf_exempt
def patient_request(request):
    if request.method == 'POST':
        hospital_id_from=request.POST['hospital_id_from']
        hospital_id_from_endpoint = request.POST['hospital_id_from_url']
        report_id_from = request.POST.getlist('report_ids')
        hospital_id_to= request.POST['hospital_id_to']
        re_encryption_key_list = request.POST.getlist('re_encryption_key_list')
        encrypted_document_received = call_for_document(hospital_id_from_endpoint,report_id_from)
        if encrypted_document_received:
            return HttpResponse("received")

def hospital_from(request):
    pass

def hospital_to():
    # send a post request to hosbital_b
    pass