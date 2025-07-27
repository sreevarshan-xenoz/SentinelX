# SentinelX Dockerfile

# Use Python 3.9 as the base image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    tcpdump \
    tshark \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create necessary directories if they don't exist
RUN mkdir -p /app/data /app/logs

# Set permissions for network capture
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.9

# Expose API port
EXPOSE 8000

# Command to run the application
CMD ["python", "src/api/api_server.py"]