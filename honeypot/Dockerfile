FROM python:3.11-slim

WORKDIR /app

# install dependencies first so Docker caches this layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy source
COPY . .

# create a non-root user — good security practice even for a honeypot
RUN useradd -m -u 1001 honeypot
USER honeypot

CMD ["python", "main.py"]
