FROM alpine

RUN apk update
RUN apk add --update \
    python3 \
    python3-dev \
    py-pip \
    build-base \
    make \
    git \
    bash \
  && pip install virtualenv \
  && rm -rf /var/cache/apk/*
COPY ./ /app
WORKDIR /app
RUN pip3 install -r requirements.txt
CMD make