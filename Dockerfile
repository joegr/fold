FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py tests.py ./

# Default: run the server
EXPOSE 5000
CMD ["python", "app.py"]
