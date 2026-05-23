FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY conpot_forwarder.py .

# /var/log/conpot is mounted as a read-only volume from the conpot container
USER nobody

ENTRYPOINT ["python", "-u", "/app/conpot_forwarder.py"]
