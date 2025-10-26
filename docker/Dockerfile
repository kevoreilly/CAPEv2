FROM python:3.11-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends git libgraphviz-dev tcpdump libcap2-bin iproute2 libjansson-dev libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash cape

RUN pip install --no-cache-dir poetry

RUN poetry config virtualenvs.create false

RUN mkdir -p /etc/poetry/bin && ln -s $(which poetry) /etc/poetry/bin/poetry
RUN mkdir -p /opt && ln -s /cape /opt/CAPEv2

WORKDIR /cape

COPY pyproject.toml poetry.lock* ./

RUN poetry install --no-interaction --no-ansi --no-root

COPY . .

RUN poetry install --no-interaction --no-ansi

RUN pip install --no-cache-dir -U flare-floss
RUN bash extra/yara_installer.sh

RUN bash docker/pcap.sh

RUN bash conf/copy_configs.sh
RUN chown -R cape:cape /cape

USER cape

CMD ["bash", "docker/run.sh"]