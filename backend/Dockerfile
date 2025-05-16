# Use python:3.9-slim as the base image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install OS-level dependencies for Scapy and packet analysis
# Added tcpdump for debugging raw packets during development
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# NIDS runs on 5000, WAF on 5001, and cleartext sim on 8080
EXPOSE 5000 5001 8080

CMD ["python", "app.py"]
