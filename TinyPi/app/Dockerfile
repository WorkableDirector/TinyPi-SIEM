FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /data

EXPOSE 8000 5514/udp

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]