FROM python:3.12-slim

# tcpdump: filtros BPF do Scapy (--filter) | iputils-ping: tráfego do modo --demo
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer.py .

VOLUME /data
ENTRYPOINT ["python", "-u", "analyzer.py"]
