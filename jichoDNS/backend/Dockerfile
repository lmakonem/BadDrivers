FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Download free GeoLite2-City database for IP geolocation
# Uses the P3TERX mirror which redistributes MaxMind's free databases
RUN mkdir -p /app/data && \
    curl -fsSL "https://git.io/GeoLite2-City.mmdb" -o /app/data/GeoLite2-City.mmdb || \
    curl -fsSL "https://github.com/P3TERX/GeoLite.info/raw/master/GeoLite2-City.mmdb" -o /app/data/GeoLite2-City.mmdb || \
    curl -fsSL "https://raw.githubusercontent.com/GitSquared/node-geolite2-redist/master/redist/GeoLite2-City.mmdb" -o /app/data/GeoLite2-City.mmdb || \
    echo "WARNING: Could not download GeoLite2 database. GeoIP lookups will be unavailable."

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser && \
    chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Default command
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
