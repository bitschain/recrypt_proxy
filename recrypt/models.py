from django.db import models

# Create your models here.

class logs(models.Model):
    log_id = models.AutoField(primary_key=True)
    hospital_id_from = models.IntegerField()
    hospital_id_to = models.IntegerField()
    report_id_from = models.CharField(max_length=50)
    created = models.DateTimeField(auto_now_add=True)
    is_deleted = models.BooleanField(default=False)
    # reencryption_key = models.TextField()
