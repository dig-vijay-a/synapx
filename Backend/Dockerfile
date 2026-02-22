# Dockerfile for TEE Worker Container
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy TEE worker files
COPY utils/ ./utils/
COPY config.py .

# Create uploads directory for mounted volumes
RUN mkdir -p /app/CloudVault

# Set environment to unbuffered for immediate stdout/stderr
ENV PYTHONUNBUFFERED=1

# Run a dummy command that keeps the container alive for `docker exec`
# Each search will be executed via `docker exec container python utils/tee_worker.py`
CMD ["tail", "-f", "/dev/null"]
