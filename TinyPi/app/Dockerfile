FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy everything from app folder (including static + templates)
COPY . .

# Make sure static exists inside image
RUN mkdir -p /app/static

EXPOSE 8000 5514/udp

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

