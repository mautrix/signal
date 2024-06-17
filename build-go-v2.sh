#!/bin/sh
MAUTRIX_VERSION=$(cat go.mod | grep 'maunium.net/go/mautrix ' | awk '{ print $2 }')
GO_LDFLAGS="-X main.Tag=$(git describe --exact-match --tags 2>/dev/null) -X main.Commit=$(git rev-parse HEAD) -X 'main.BuildTime=`date -Iseconds`' -X 'maunium.net/go/mautrix.GoModVersion=$MAUTRIX_VERSION'"
if [ "$DBG" = 1 ]; then
    GO_GCFLAGS='all=-N -l'
else
    GO_LDFLAGS="-s -w ${GO_LDFLAGS}"
fi
go build -gcflags="$GO_GCFLAGS" -ldflags="$GO_LDFLAGS" -o mautrix-signal-v2 ./cmd/mautrix-signal-v2 "$@"
