## Element fork

The Element fork includes the following changes:
- [User activity tracking](https://github.com/vector-im/mautrix-signal/tree/hs/activity-blocking)
- [Add additional metrics to the bridge](https://github.com/mautrix/signal/pull/164)
- [Make handledMatrixMessage log at info, and include more details](https://github.com/vector-im/mautrix-signal/pull/6)

Some changes that appear here may get upstreamed to https://github.com/mautrix/signal, and will be removed from
the list when they appear in both versions.

Tagged versions will appear as `v{UPSTREAM-VERSION}-mod-{VERSION}`

E.g. The third modification release to 1.0 of the upstream bridge would be `v1.0-mod-3`.

# mautrix-signal
![Languages](https://img.shields.io/github/languages/top/mautrix/signal.svg)
[![License](https://img.shields.io/github/license/mautrix/signal.svg)](LICENSE)
[![Release](https://img.shields.io/github/release/mautrix/signal/all.svg)](https://github.com/mautrix/signal/releases)
[![GitLab CI](https://mau.dev/mautrix/signal/badges/master/pipeline.svg)](https://mau.dev/mautrix/signal/container_registry)
[![Code style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)

A Matrix-Signal puppeting bridge.

## Documentation
All setup and usage instructions are located on
[docs.mau.fi](https://docs.mau.fi/bridges/python/signal/index.html).
Some quick links:

* [Bridge setup](https://docs.mau.fi/bridges/python/setup/index.html?bridge=signal)
  (or [with Docker](https://docs.mau.fi/bridges/python/signal/setup-docker.html))
* Basic usage: [Authentication](https://docs.mau.fi/bridges/python/signal/authentication.html)

### Features & Roadmap
[ROADMAP.md](https://github.com/mautrix/signal/blob/master/ROADMAP.md)
contains a general overview of what is supported by the bridge.

## Discussion
Matrix room: [`#signal:maunium.net`](https://matrix.to/#/#signal:maunium.net)
