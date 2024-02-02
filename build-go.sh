#!/bin/sh
MAUTRIX_VERSION=$(cat go.mod | grep 'maunium.net/go/mautrix ' | awk '{ print $2 }')
GO_LDFLAGS="-s -w -X main.Tag=$(git describe --exact-match --tags 2>/dev/null) -X main.Commit=$(git rev-parse HEAD) -X 'main.BuildTime=`date '+%b %_d %Y, %H:%M:%S'`' -X 'maunium.net/go/mautrix.GoModVersion=$MAUTRIX_VERSION'"
if [[ $DBG -eq 1 ]]; then
    GO_GCFLAGS='all=-N -l'
fi
go build -gcflags="$GO_GCFLAGS" -ldflags="$GO_LDFLAGS" -o mautrix-signal
