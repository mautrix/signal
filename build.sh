#!/bin/sh
git submodule init
git submodule update
make GO_EXTRA_OPTS="$*"
