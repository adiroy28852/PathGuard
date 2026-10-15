FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY graph_api/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY graph_api ./graph_api

EXPOSE 8100
CMD ["uvicorn", "graph_api.main:app", "--host", "0.0.0.0", "--port", "8100"]
