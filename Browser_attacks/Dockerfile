FROM handsonsecurity/seed-ubuntu:large
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y firefox && pip install --upgrade pip setuptools wheel && apt-get install -y gcc && apt install -y libnetfilter-queue-dev && apt-get install -y python3-dev && pip install netfilterqueue && pip install scapy-http
CMD ["/bin/bash"]
