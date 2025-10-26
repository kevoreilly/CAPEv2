FROM mirror.gcr.io/library/python:3.11-bookworm

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends git libgraphviz-dev tcpdump libcap2-bin iproute2

RUN useradd -ms /bin/bash cape

COPY pcap.sh pcap.sh
RUN bash pcap.sh

COPY install.sh install.sh
RUN bash install.sh

WORKDIR /cape

RUN bash conf/copy_configs.sh
RUN chown -R cape:cape /cape

COPY run.sh run.sh

USER cape
ENTRYPOINT ["bash", "run.sh"]