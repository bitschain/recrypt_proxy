from django.urls import path

from recrypt import views

urlpatterns = [
    path('transfer_doc_request', views.patient_request),
    # path('', views.hospital_from),

]