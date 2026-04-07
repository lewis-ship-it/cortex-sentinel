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

# Install apktool (APK decompiler for mobile scanning)
RUN wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar \
        -O /usr/local/bin/apktool.jar && \
    wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
        -O /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool /usr/local/bin/apktool.jar

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Note: The actual command to run is handled in docker-compose.yml