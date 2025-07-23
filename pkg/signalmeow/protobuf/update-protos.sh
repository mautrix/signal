#!/bin/bash
set -euo pipefail

ANDROID_GIT_REVISION=${1:-dbd79cd0a52d7d1594f70a4ba5a68c8fc3efa5e8}
DESKTOP_GIT_REVISION=${1:-07a05f3dd6f7fd07a1faebd8dd046d2b87da6c07}

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
