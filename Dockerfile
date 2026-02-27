# Use a slim Python image for fast builds and small footprint
FROM python:3.11-slim

# CSIAC NetSec: Create non-root user and group
RUN groupadd --system appgroup && \
    useradd --system --gid appgroup --no-create-home appuser

# Set environment variables to ensure output is logged immediately
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# CSIAC NetSec: Switch to non-root user
USER appuser

# Expose the Cloud Run default port
EXPOSE 8080

# CSIAC NetSec: Container health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/_stcore/health')" || exit 1

# Run the application
ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8080", "--server.address=0.0.0.0"]
