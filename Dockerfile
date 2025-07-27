# SentinelX Dockerfile
FROM python:3.9-slim

LABEL maintainer="SentinelX Team"
LABEL description="SentinelX - AI-Powered Network Security Monitoring"

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Install the package
RUN pip install -e .

# Expose port for web dashboard
EXPOSE 8050

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Default command to run the web dashboard
CMD ["python", "-m", "src.visualization", "web", "--host", "0.0.0.0"]