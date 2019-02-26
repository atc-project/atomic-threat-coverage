FROM alpine

RUN apk update
RUN apk add --update \
    python3 \
    python3-dev \
    py-pip \
    build-base \
    make \
    git \
    bash
COPY ./ /app
WORKDIR /app
RUN pip3 install -r requirements.txt
RUN apk del py-pip python3-dev && rm -rf /var/cache/apk/*
CMD make