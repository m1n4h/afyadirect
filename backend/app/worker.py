from celery import Celery
from .config import settings

app = Celery(
    'afyadirect',
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND
)

app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Africa/Dar_es_Salaam',
    enable_utc=True,
)

@app.task
def health_check():
    """Health check task for Celery."""
    return "Celery worker is alive"