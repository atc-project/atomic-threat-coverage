FROM alpine
COPY ./ /app
WORKDIR /app

RUN apk update; \
    apk add --update \
    python3 \
    python3-dev \
    py-pip \
    git \
    bash; \
    pip3 install -r requirements.txt && \
    git submodule init && \
	git submodule update && \
	git submodule foreach git pull origin master && \
	cp -r detection_rules/sigma/rules/windows/*/*.yml detection_rules/ && \
    apk del py-pip python3-dev git && rm -rf /var/cache/apk/*
CMD /app/docker-entrypoint.sh