FROM alpine:3.14

ARG TARGETARCH=amd64

RUN apk add --no-cache \
      python3 py3-pip py3-setuptools py3-wheel \
      py3-virtualenv \
      py3-pillow \
      py3-aiohttp \
      py3-magic \
      py3-ruamel.yaml \
      py3-commonmark \
      py3-qrcode \
      py3-phonenumbers \
      py3-prometheus-client \
      # Other dependencies
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
 && apk del .build-deps

COPY . /opt/mautrix-signal
RUN apk add git \
  && apk add --virtual .build-deps python3-dev libffi-dev build-base \
  && pip3 install .[all] \
  && pip3 install -r requirements.txt -r optional-requirements.txt \
  && pip3 install 'git+https://github.com/vector-im/mautrix-python@v0.11.4-mod-2#egg=mautrix' \
  && apk del git \
  && apk del .build-deps \
  # This doesn't make the image smaller, but it's needed so that the `version` command works properly
  && cp mautrix_signal/example-config.yaml . && rm -rf mautrix_signal

VOLUME /data

CMD ["/opt/mautrix-signal/docker-run.sh"]
