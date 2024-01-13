#!/bin/bash
set -euo pipefail

ANDROID_GIT_REVISION=${1:-c725a2fabb76f88d555c9f8b3c4f1cbdde4d4593}
DESKTOP_GIT_REVISION=${1:-060c58be527396918fa3753ace4f9f38d7c67876}

update_proto() {
  case "$1" in
    Signal-Android)
      prefix="libsignal-service/src/main/protowire/"
      GIT_REVISION=$ANDROID_GIT_REVISION
      ;;
    Signal-Desktop)
      prefix="protos/"
      GIT_REVISION=$DESKTOP_GIT_REVISION
      ;;
  esac
  echo https://raw.githubusercontent.com/signalapp/${1}/${GIT_REVISION}/${prefix}${2}
  curl -LOf https://raw.githubusercontent.com/signalapp/${1}/${GIT_REVISION}/${prefix}${2}
}


update_proto Signal-Android Groups.proto
update_proto Signal-Android Provisioning.proto
update_proto Signal-Android SignalService.proto
update_proto Signal-Android StickerResources.proto
update_proto Signal-Android WebSocketResources.proto

update_proto Signal-Desktop DeviceName.proto
update_proto Signal-Desktop UnidentifiedDelivery.proto
update_proto Signal-Desktop ContactDiscovery.proto
