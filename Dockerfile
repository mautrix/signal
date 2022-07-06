FROM docker.io/alpine:3.16

ARG TARGETARCH=amd64

RUN apk add --no-cache \
      python3 py3-pip py3-setuptools py3-wheel \
      py3-pillow \
      py3-aiohttp \
      py3-magic \
      py3-ruamel.yaml \
      py3-commonmark \
      py3-qrcode \
      py3-phonenumbers \
      #py3-prometheus-client \
      # Other dependencies
      ffmpeg \
      py3-cryptography \
      py3-protobuf \
      py3-sniffio \
      py3-rfc3986 \
      py3-idna \
      py3-h11 \
      ca-certificates \
      su-exec \
      # encryption
      py3-olm \
      py3-cffi \
      py3-pycryptodome \
      py3-unpaddedbase64 \
      py3-future \
      bash \
      curl \
      jq \
      yq

COPY requirements.txt /opt/mautrix-signal/requirements.txt
COPY optional-requirements.txt /opt/mautrix-signal/optional-requirements.txt
WORKDIR /opt/mautrix-signal
RUN apk add --virtual .build-deps python3-dev libffi-dev build-base \
 && pip3 install --no-cache-dir -r requirements.txt -r optional-requirements.txt \
 && apk del .build-deps

COPY . /opt/mautrix-signal
RUN apk add git && pip3 install --no-cache-dir .[all] && apk del git \
  # This doesn't make the image smaller, but it's needed so that the `version` command works properly
  && cp mautrix_signal/example-config.yaml . && rm -rf mautrix_signal .git build

VOLUME /data
ENV UID=1337 GID=1337

CMD ["/opt/mautrix-signal/docker-run.sh"]
