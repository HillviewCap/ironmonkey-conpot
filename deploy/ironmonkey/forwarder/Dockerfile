FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY conpot_forwarder.py .

# /var/log/conpot is mounted read-only from the conpot container (the forwarder
# only tails conpot.json there). The dead-letter spool lives on a dedicated
# named volume mounted at /var/spool/conpot-forwarder, owned by nobody so the
# unprivileged process can append failed events. The directory is created in
# the image so Docker copies its ownership/perms into the named volume on
# first mount.
RUN mkdir -p /var/spool/conpot-forwarder \
    && chown nobody:nogroup /var/spool/conpot-forwarder \
    && chmod 0700 /var/spool/conpot-forwarder

USER nobody

ENTRYPOINT ["python", "-u", "/app/conpot_forwarder.py"]
