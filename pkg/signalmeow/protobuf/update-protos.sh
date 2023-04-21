#!/bin/bash
set -euo pipefail

ANDROID_GIT_REVISION=${1:-7275b95b583b64144fc7f935144b0a17c45244e7}
DESKTOP_GIT_REVISION=${1:-d198ceda4bb5dfbc7c13a64b8355df6477952210}

update_proto() {
  case "$1" in
    Signal-Android)
      prefix="libsignal/service/src/main/proto/"
      GIT_REVISION=$ANDROID_GIT_REVISION
      ;;
    Signal-Desktop)
      prefix="protos/"
      GIT_REVISION=$DESKTOP_GIT_REVISION
      ;;
  esac
  curl -sLOf https://raw.githubusercontent.com/signalapp/${1}/${GIT_REVISION}/${prefix}${2}
}


update_proto Signal-Android Groups.proto
update_proto Signal-Android Provisioning.proto
update_proto Signal-Android SignalService.proto
update_proto Signal-Android StickerResources.proto
update_proto Signal-Android WebSocketResources.proto

update_proto Signal-Desktop DeviceName.proto
update_proto Signal-Desktop UnidentifiedDelivery.proto
