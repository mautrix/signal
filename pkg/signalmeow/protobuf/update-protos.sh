#!/bin/bash
set -euo pipefail

ANDROID_GIT_REVISION=${1:-aa9591211ba0c77376318bdd5f014e064b8e8de4}
DESKTOP_GIT_REVISION=${1:-a0af83d7488930c213a7b6dd554490ebe9e65628}

update_proto() {
  case "$1" in
    Signal-Android)
      REPO="Signal-Android"
      prefix="lib/libsignal-service/src/main/protowire/"
      GIT_REVISION=$ANDROID_GIT_REVISION
      ;;
    Signal-Android-Archive)
      REPO="Signal-Android"
      prefix="lib/archive/src/main/protowire/"
      GIT_REVISION=$ANDROID_GIT_REVISION
      ;;
    Signal-Android-Network)
      REPO="Signal-Android"
      prefix="core/network/src/main/protowire/"
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
update_proto Signal-Android-Network WebSocketResources.proto
update_proto Signal-Android StorageService.proto

update_proto Signal-Android-Archive Backup.proto
mv Backup.proto backuppb/Backup.proto

update_proto Signal-Desktop DeviceName.proto
# TODO these were moved to libsignal only
#update_proto Signal-Desktop UnidentifiedDelivery.proto
#update_proto Signal-Desktop ContactDiscovery.proto
