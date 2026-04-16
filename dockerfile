FROM python:3.11-slim

WORKDIR /app

# Install system dependencies first (cached unless this layer changes)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first for better caching
COPY requirements.txt .

# Install Python dependencies (cached unless requirements.txt changes)
RUN pip install --no-cache-dir -r requirements.txt

# Playwright browsers installation (cached unless this step changes)
# This runs BEFORE copying app code so rebuilds don't re-download browsers
RUN playwright install --with-deps

# Copy app code last (changes frequently, doesn't invalidate previous layers)
COPY . /app

CMD ["python", "api/main.py"]
