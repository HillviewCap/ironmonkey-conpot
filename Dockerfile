# Stage 1: Build stage
FROM python:3.12 AS conpot-builder

# Install required dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /opt/conpot

# Copy the source code to the container
COPY . .

# Install uv and project dependencies
RUN pip3 install --no-cache-dir uv \
    && uv pip install --system --no-cache .

# Stage 2: Runtime stage
FROM python:3.12-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN adduser --disabled-password --gecos "" conpot

# Create required directories and set permissions
RUN mkdir -p /var/log/conpot \
    && mkdir -p /usr/local/lib/python3.12/site-packages/conpot/tests/data/data_temp_fs/ftp \
    && mkdir -p /usr/local/lib/python3.12/site-packages/conpot/tests/data/data_temp_fs/tftp \
    && chown -R conpot:conpot /var/log/conpot \
    && chown -R conpot:conpot /usr/local/lib/python3.12/site-packages/conpot/tests/data

# Set working directory and copy dependencies from build stage
WORKDIR /home/conpot
COPY --from=conpot-builder /usr/local/lib/python3.12/ /usr/local/lib/python3.12/
COPY --from=conpot-builder /usr/local/bin/ /usr/local/bin/

# Watchdog for gevent hub starvation. Runs as PID 1 with conpot as its child;
# see the module docstring for why a Docker HEALTHCHECK cannot do this job.
COPY deploy/ironmonkey/conpot_supervisor.py /usr/local/bin/conpot-supervisor
RUN chmod +x /usr/local/bin/conpot-supervisor

# Set permissions for non-root user
RUN chown -R conpot:conpot /home/conpot

# Switch to non-root user
USER conpot
ENV PATH=$PATH:/home/conpot/.local/bin
ENV USER=conpot

# Reports the supervisor's verdict. Detection and remediation both live in the
# supervisor — this only surfaces the state to `docker ps` / `docker inspect`,
# because Docker never restarts a container for being unhealthy.
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s --retries=2 \
    CMD test "$(cat /tmp/conpot-health 2>/dev/null)" = "ok"

# Set the default command. CMD args are appended to the supervisor, which
# execs them as `conpot <args>`, so the command contract is unchanged.
ENTRYPOINT ["/usr/local/bin/conpot-supervisor"]
CMD ["--template", "default", "--logfile", "/var/log/conpot/conpot.log", "-f", "--temp_dir", "/tmp"]
