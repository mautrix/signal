# mautrix-signalgo
![Languages](https://img.shields.io/github/languages/top/mautrix/signalgo.svg)
[![License](https://img.shields.io/github/license/mautrix/signalgo.svg)](LICENSE)
[![GitLab CI](https://mau.dev/mautrix/signalgo/badges/main/pipeline.svg)](https://mau.dev/mautrix/signalgo/container_registry)
[![Code style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)

Go rewrite of mautrix-signal.

## Documentation
All setup and usage instructions are located on
[docs.mau.fi](https://docs.mau.fi/bridges/go/signal/index.html).
Some quick links:

* [Bridge setup](https://docs.mau.fi/bridges/go/setup.html?bridge=signalgo)
  (or [with Docker](https://docs.mau.fi/bridges/general/docker-setup.html?bridge=signalgo))
* Basic usage: [Authentication](https://docs.mau.fi/bridges/go/signal/authentication.html)

## Building
- Clone this repo with submodules
  (`git submodule init && git submodule update`)
- Ensure you have cmake and libolm headers installed
  (ie. `brew install cmake libolm`)
- Ensure your env variables are correct
	ie.
	```
	export LIBRARY_PATH=/opt/homebrew/lib
	export C_INCLUDE_PATH=/opt/homebrew/include
	```
- Make it (`make`)

## Discussion
Matrix room: [`#signal:maunium.net`](https://matrix.to/#/#signal:maunium.net)
