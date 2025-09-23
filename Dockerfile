FROM python:3.13-slim

# Prevents Python from writing pyc files & ensures stdout flush
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY app.py .

# Expose port 8080
EXPOSE 8080

CMD ["python", "app.py"]
