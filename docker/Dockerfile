FROM python:3.11-bookworm

RUN apt-get update ; \
    apt-get upgrade -y ; \
    apt-get install -y git libgraphviz-dev tcpdump

COPY pcap.sh pcap.sh

RUN useradd -ms /bin/bash cape

COPY install.sh install.sh
RUN bash install.sh

WORKDIR /cape

RUN bash conf/copy_configs.sh
RUN chown -R cape:cape /cape

COPY run.sh run.sh

USER cape
ENTRYPOINT ["bash", "run.sh"]
