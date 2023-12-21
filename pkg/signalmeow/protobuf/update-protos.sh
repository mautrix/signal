#!/bin/bash
set -euo pipefail

ANDROID_GIT_REVISION=${1:-e17b07bb12110c0ebeae193cb6fad35d33b57d40}
DESKTOP_GIT_REVISION=${1:-c6c072319993fefd9fcfab55ca77dc75263bc875}

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
