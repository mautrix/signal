#!/bin/bash
set -euo pipefail

ANDROID_GIT_REVISION=${1:-aa9c87ee67364a28977a2a5ba3bb7f5e715e19a0}
DESKTOP_GIT_REVISION=${1:-3f0536f5a58b6a20949690afd76093f41931843c}

update_proto() {
  case "$1" in
    Signal-Android)
      REPO="Signal-Android"
      prefix="libsignal-service/src/main/protowire/"
      GIT_REVISION=$ANDROID_GIT_REVISION
      ;;
    Signal-Android-App)
      REPO="Signal-Android"
      prefix="app/src/main/protowire/"
      GIT_REVISION=$ANDROID_GIT_REVISION
      ;;
    Signal-Desktop)
      REPO="Signal-Desktop"
      prefix="protos/"
      GIT_REVISION=$DESKTOP_GIT_REVISION
      ;;
  esac
  echo https://raw.githubusercontent.com/signalapp/${REPO}/${GIT_REVISION}/${prefix}${2}
  curl -LOf https://raw.githubusercontent.com/signalapp/${REPO}/${GIT_REVISION}/${prefix}${2}
}


update_proto Signal-Android Groups.proto
update_proto Signal-Android Provisioning.proto
update_proto Signal-Android SignalService.proto
update_proto Signal-Android StickerResources.proto
update_proto Signal-Android WebSocketResources.proto
update_proto Signal-Android StorageService.proto

update_proto Signal-Android-App Backup.proto
mv Backup.proto backuppb/Backup.proto

update_proto Signal-Desktop DeviceName.proto
update_proto Signal-Desktop UnidentifiedDelivery.proto
# Android has CDSI.proto too, but the types have more generic names (since android uses a different package name)
update_proto Signal-Desktop ContactDiscovery.proto
