# v0.2.2 (2022-01-15)

Target signald version: [v0.16.1](https://gitlab.com/signald/signald/-/releases/0.16.1)

### Added
* Support for disappearing messages.
  * Disabled by default in group chats, as there's no way to delete messages
    from the view of a single Matrix user. For single-user bridges, it's safe
    to enable the `enable_disappearing_messages_in_groups` config option.
* Notifications about incoming calls.
* Support for voice messages with [MSC3245].
* Support for incoming contact share messages.
* Support for long text messages from Signal.

### Improved
* Formatted all code using [black](https://github.com/psf/black)
  and [isort](https://github.com/PyCQA/isort).
* Moved most relay mode code to mautrix-python to be shared with other bridges.
* The bridge will now queue messages temporarily if signald is down while sending.
* Removed legacy community-related features.
* Updated remaining things to use signald's v1 API.

### Fixed
* Fixed empty DM rooms being unnecessarily created when receiving
  non-bridgeable events (e.g. profile key updates).
* Fixed duplicate rooms being created in certain cases due to the room mapping
  cache not working.
* Fixed replies to attachments not rendering on Signal iOS properly.

[MSC3245]: https://github.com/matrix-org/matrix-doc/pull/3245

# v0.2.1 (2021-11-28)

Target signald version: [v0.15.0](https://gitlab.com/signald/signald/-/releases/0.15.0)

### Added
* Support for Matrix->Signal redactions.
* Error messages to Matrix when sending to Signal fails.
* Custom flag to invite events that will be auto-accepted with double puppeting.
* Command to get group invite link.
* Support for custom bridge bot welcome messages
  (thanks to [@justinbot] in [#146]).
* Option to disable federation in portal rooms.
* Option to prevent users from registering the bridge as their primary device
  (thanks to [@tadzik] in [#153]).
* Extremely experimental support for SQLite. It's probably broken in some
  cases, so don't use it.

### Improved
* Increased line length limit for signald socket (was causing the connection to
  fail when there was too much data going through).
* Improved Signal disconnection detection (mostly affects prometheus metrics).
* Updated provisioning API `/link/wait` endpoint to return HTTP 400 if signald
  loses connection to Signal.

### Fixed
* Fixed bugs with automatic migration of Matrix ghosts from phone number to
  UUID format.
* Fixed handling empty Signal avatar files.

[@justinbot]: https://github.com/justinbot
[@tadzik]: https://github.com/tadzik
[#146]: https://github.com/mautrix/signal/pull/146
[#153]: https://github.com/mautrix/signal/pull/153

# v0.2.0 (2021-08-07)

Target signald version: [v0.14.1](https://gitlab.com/signald/signald/-/releases/0.14.1)

**N.B.** Docker images have moved from `dock.mau.dev/tulir/mautrix-signal` to
`dock.mau.dev/mautrix/signal`. New versions are only available at the new path.

### Added
* Relay mode (see [docs](https://docs.mau.fi/bridges/general/relay-mode.html)).
* Added captcha parameter to help text of register command.
* Option to delete unknown accounts from signald when starting the bridge.

### Improved
* Contact info is now synced when other devices send contact list updates.
* Contact avatars will now be used if profile avatar isn't available and
  contact names are allowed.
* Linking a new device or registering now uses the `overwrite` param in
  signald, which means it will force-login even if there is an existing
  signald session with the same phone number.
* Updated Docker image to Alpine 3.14.

### Fixed
* Fixed Signal delivery receipts being handled as read receipts.
* Fixed logging out causing signald to get into a bad state.
* Fixed handling conflicting puppet rows when finding UUID.

# v0.1.1 (2021-04-07)

Target signald version: [v0.13.1](https://gitlab.com/signald/signald/-/tags/0.13.1)

### Added
* Support for group v2 avatars.
* Syncing of group permissions from Signal.
* Support for accepting Signal group invites.
* Support for Matrix->Signal group name and avatar changes.
* Support for real-time group info updates from Signal.
* Hidden captcha support in register command.
* Command to mark safety numbers as trusted.
* Workaround for Element iOS image rendering bug
  (thanks to [@celogeek] in [#57]).

### Improved
* Commands that take phone numbers now tolerate unnecessary characters a bit better.
* Updated to signald v1 protocol for most requests.

### Fixed
* Failure to bridge attachments if the `outgoing_attachment_dir` didn't exist.
* Errors with no messages from signald not being parsed properly.

[@celogeek]: https://github.com/celogeek
[#57]: https://github.com/mautrix/signal/pull/57

# v0.1.0 (2021-02-05)

Initial release.
