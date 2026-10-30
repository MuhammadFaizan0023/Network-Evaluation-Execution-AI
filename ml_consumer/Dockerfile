FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=300 -r requirements.txt

COPY consumer.py .

# Bake the ML model artifacts (web CNN + IoT XGBoost) into the single shared image.
COPY model/ /app/model/

CMD ["python", "-u", "consumer.py"]