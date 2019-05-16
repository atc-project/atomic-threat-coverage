FROM alpine
COPY ./ /app
WORKDIR /app

RUN apk update; \
    apk add --update \
    python3 \
    python3-dev \
    py-pip \
    bash; \
    pip3 install -r requirements.txt; \
    apk del py-pip python3-dev; \
    rm -rf /var/cache/apk/* ; \
    rm -rf Atomic_Threat_Coverage;
CMD /app/docker-entrypoint.sh