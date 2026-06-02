from django.urls import path
from . import views


urlpatterns = [
    # header:
    path('', views.home, name='home'),
    path('features/', views.features, name='features'),
    path('about/', views.about, name='about'),
    path('support/', views.support, name='support'),
    path('analyze/', views.analyze, name='analyze'),
    path('analyze/report.pdf/', views.download_report_pdf, name='download_report_pdf'),
]
