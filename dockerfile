# dockerfile

# Use a slim Python image for a smaller footprint
FROM python:3.12-slim

# Set environment variables to prevent Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
# - gcc / libpq-dev : needed for some security/db libraries
# - default-jre     : required by apktool (Java binary)
# - wget            : to download apktool jar
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    default-jre \
    wget \
    && rm -rf /var/lib/apt/lists/*



# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Note: The actual command to run is handled in docker-compose.yml