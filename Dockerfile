FROM alpine
COPY ./ /app
WORKDIR /app

RUN apk update; \
    apk add --update \
    python3 \
    python3-dev \
    py-pip \
    gcc \
    musl-dev \
    bash;

RUN pip3 install -r requirements.txt;
    
RUN apk del python3-dev \
    gcc \
    musl-dev;

RUN rm -rf /var/cache/apk/* ; \
    rm -rf Atomic_Threat_Coverage;

CMD /app/docker-entrypoint.sh
