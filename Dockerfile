# Dockerfile
# Use a secure and lightweight Python base image
FROM python:3.10-slim

# 1. Install System Dependencies (Tor) and Gunicorn
RUN apt-get update && apt-get install -y --no-install-recommends \
    tor \
    gunicorn \
    && rm -rf /var/lib/apt/lists/*

# 2. Set the working directory and copy the project files
WORKDIR /app
COPY . /app

# 3. Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 4. Set environment variables for runtime
ENV PYTHONUNBUFFERED=1
ENV PORT=5001
ENV TOR_BINARY_PATH=/usr/bin/tor
ENV DATABASE_DIR=/app/data/ 

# Create a dedicated directory for state/persistence (database, keys, etc.)
RUN mkdir -p /app/data

# 5. Expose the application port
EXPOSE 5001

# 6. Define the secure startup command (CMD)
# Executes Tor in the background (&) and then starts the Flask app using Gunicorn.
# The 'app:app' assumes your Flask instance is named 'app' inside 'app.py'.
CMD (tor -f /etc/tor/torrc &) && gunicorn app:app --bind 0.0.0.0:$PORT
