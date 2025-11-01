FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY terrasafe/ ./terrasafe/
COPY models/ ./models/

EXPOSE 8000

CMD ["python", "-m", "terrasafe.api"]
