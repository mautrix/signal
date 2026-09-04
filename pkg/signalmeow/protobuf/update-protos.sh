#!/bin/bash
set -euo pipefail

ANDROID_GIT_REVISION=${1:-46d6eeb2f3d3e12e6938151a8dbd2a33b5604b1f}

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
    Signal-Android-Util)
      REPO="Signal-Android"
      prefix="core/util-jvm/src/main/protowire/"
      GIT_REVISION=$ANDROID_GIT_REVISION
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
update_proto Signal-Android-Util DeviceName.proto

update_proto Signal-Android-Archive Backup.proto
mv Backup.proto backuppb/Backup.proto

cp -f ../../libsignalgo/libsignal/rust/net/src/proto/cds2.proto cds2pb/cds2.proto
