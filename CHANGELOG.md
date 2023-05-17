# v0.4.3 (2023-05-17)

Target signald version: [v0.23.2](https://gitlab.com/signald/signald/-/releases/0.23.2)

* Added option to not set name/avatar for DM rooms even if the room is encrypted.
* Added options to automatically ratchet/delete megolm sessions to minimize
  access to old messages.
* Added command to request group/contact sync from primary device.
* Added error notices if incoming attachments are dropped.
* Fixed bugs with creating groups.
* Fixed handling changes to disappearing message timer in groups.

## Changes by [@maltee1]

* Added bridging of group join requests on Signal to knocks on Matrix ([#275]).
* Added bridging of banned users from Signal to Matrix ([#275]).
* Added admin command to force logout other Matrix users from the bridge ([#359]).
* Added `submit-challenge` command to submit captcha codes when encountering
  ratelimits on sending messages ([#320]).
* Added invite command for inviting Signal users to a group by phone number ([#285]).
* Added support for bridging Matrix invites to Signal via relay user ([#285]).
* Added automatic group creation when inviting multiple Signal ghosts to a
  non-DM room ([#294]).
* Fixed ghost user getting kicked from Matrix room when trying to invite a user
  who's already in the group on Signal ([#345]).
* Fixed bridging power levels from Signal for users who are logged into the
  bridge, but don't have double puppeting enabled ([#333]).

[#275]: https://github.com/mautrix/signal/pull/275
[#285]: https://github.com/mautrix/signal/pull/285
[#294]: https://github.com/mautrix/signal/pull/294
[#320]: https://github.com/mautrix/signal/pull/320
[#333]: https://github.com/mautrix/signal/pull/333
[#345]: https://github.com/mautrix/signal/pull/345
[#359]: https://github.com/mautrix/signal/pull/359

# v0.4.2 (2022-12-03)

Target signald version: [v0.23.0](https://gitlab.com/signald/signald/-/releases/0.23.0)

* Fixed database schema upgrade for users who used SQLite before it was
  stabilized in v0.4.1.
* Fixed error in commands that use phone numbers (like `!signal pm`).
* Fixed updating private chat portal metadata when Signal user info changes.
* Updated Docker image to Alpine 3.17.

# v0.4.1 (2022-10-28)

Target signald version: [v0.23.0](https://gitlab.com/signald/signald/-/releases/0.23.0)

* Dropped support for phone numbers as Signal user identifiers.
* Dropped support for v1 groups.
* Promoted SQLite support to non-experimental level.
* Fixed call notices not having a plaintext `body` field.
* "Implicit" messages from Signal (things like read receipts) that fail to
  decrypt will no longer send a notice to the Matrix room.
* The docker image now has an option to bypass the startup script by setting
  the `MAUTRIX_DIRECT_STARTUP` environment variable. Additionally, it will
  refuse to run as a non-root user if that variable is not set (and print an
  error message suggesting to either set the variable or use a custom command).

# v0.4.0 (2022-09-17)

Target signald version: [v0.21.1](https://gitlab.com/signald/signald/-/releases/0.21.1)

**N.B.** This release requires a homeserver with Matrix v1.1 support, which
bumps up the minimum homeserver versions to Synapse 1.54 and Dendrite 0.8.7.
Minimum Conduit version remains at 0.4.0.

### Added
* Added provisioning API for checking if a phone number is registered on Signal
* Added admin command for linking to an existing account in signald.
* Added Matrix -> Signal bridging for invites, kicks, bans and unbans
  (thanks to [@maltee1] in [#246] and [#257]).
* Added command to create Signal group for existing Matrix room
  (thanks to [@maltee1] in [#250]).
* Added Matrix -> Signal power level change bridging
  (thanks to [@maltee1] in [#260] and [#263]).
* Added join rule bridging in both directions (thanks to [@maltee1] in [#268]).
* Added Matrix -> Signal bridging of location messages
  (thanks to [@maltee1] in [#287]).
  * Since Signal doesn't have actual location messages, they're just bridged as
    map links. The link template is configurable.
* Added command to link devices when the bridge is the primary device
  (thanks to [@Craeckie] in [#221]).
* Added command to bridge existing Matrix rooms to existing Signal groups
  (thanks to [@MaximilianGaedig] in [#288]).
* Added config option to auto-enable relay mode when a specific user is invited
  (thanks to [@maltee1] in [#293]).
* Added options to make encryption more secure.
  * The `encryption` -> `verification_levels` config options can be used to
    make the bridge require encrypted messages to come from cross-signed
    devices, with trust-on-first-use validation of the cross-signing master
    key.
  * The `encryption` -> `require` option can be used to make the bridge ignore
    any unencrypted messages.
  * Key rotation settings can be configured with the `encryption` -> `rotation`
    config.

### Improved
* Improved/fixed handling of disappearing message timer changes.
* Improved handling profile/contact names and prevented them from being
  downgraded (switching from profile name to contact name or phone number).
* Updated contact list provisioning API to not block if signald needs to update
  profiles.
* Trying to start a direct chat with a non-existent phone number will now reply
  with a proper error message instead of throwing an exception
  (thanks to [@maltee1] in [#265]).
* Syncing chat members will no longer be interrupted if one of the member
  profiles is unavailable (thanks to [@maltee1] in [#270]).
* Group metadata changes are now bridged based on the event itself rather than
  resyncing the whole group, which means changes will use the correct ghost
  user instead of always using the bridge bot (thanks to [@maltee1] in [#283]).
* Added proper captcha error handling when registering
  (thanks to [@maltee1] in [#280]).
* Added user's phone number as topic in private chat portals
  (thanks to [@maltee1] in [#282]).

### Fixed
* Call start notices work again

[@Craeckie]: https://github.com/Craeckie
[@MaximilianGaedig]: https://github.com/MaximilianGaedig
[#221]: https://github.com/mautrix/signal/pull/221
[#246]: https://github.com/mautrix/signal/pull/246
[#250]: https://github.com/mautrix/signal/pull/250
[#257]: https://github.com/mautrix/signal/pull/257
[#260]: https://github.com/mautrix/signal/pull/260
[#263]: https://github.com/mautrix/signal/pull/263
[#265]: https://github.com/mautrix/signal/pull/265
[#268]: https://github.com/mautrix/signal/pull/268
[#270]: https://github.com/mautrix/signal/pull/270
[#280]: https://github.com/mautrix/signal/pull/280
[#282]: https://github.com/mautrix/signal/pull/282
[#283]: https://github.com/mautrix/signal/pull/283
[#287]: https://github.com/mautrix/signal/pull/287
[#288]: https://github.com/mautrix/signal/pull/288
[#293]: https://github.com/mautrix/signal/pull/293

# v0.3.0 (2022-04-20)

Target signald version: [v0.18.0](https://gitlab.com/signald/signald/-/releases/0.18.0)

### Important changes
* Both the signald and mautrix-signal docker images have been changed to run as
  UID 1337 by default. The migration should work automatically as long as you
  update both containers at the same time.
  * Also note that the `finn/signald` image is deprecated, you should use `signald/signald`.
    <https://signald.org/articles/install/docker/>
* Old homeservers which don't support the new `/v3` API endpoints are no longer
  supported. Synapse 1.48+, Dendrite 0.6.5+ and Conduit 0.4.0+ are supported.
  Legacy `r0` API support can be temporarily re-enabled with `pip install mautrix==0.16.0`.
  However, this option will not be available in future releases.

### Added
* Support for creating DM portals by inviting user (i.e. just making a DM the
  normal Matrix way).
* Leaving groups is now bridged to Signal (thanks to [@maltee1] in [#245]).
* Signal group descriptions are now bridged into Matrix room topics.
* Signal announcement group status is now bridged into power levels on Matrix
  (the group will be read-only for everyone except admins).
* Added optional parameter to `mark-trusted` command to set trust level
  (instead of always using `TRUSTED_VERIFIED`).
* Added option to use [MSC2246] async media uploads.
* Added provisioning API for listing contacts and starting private chats.

### Improved
* Dropped Python 3.7 support.
* Files bridged to Matrix now include the `size` field in the file `info`.
* Removed redundant `msgtype` field in sticker events sent to Matrix.
* Users who have left the group on Signal will now be removed from Matrix too.

### Fixed
* Logging into the bridge with double puppeting no longer removes your Signal
  user's Matrix ghost from DM portals with other bridge users.
* Fixed identity failure error message always saying "while sending message to
  None" instead of specifying the problematic phone number.
* Fixed `channel` -> `id` field in `m.bridge` events.

[MSC2246]: https://github.com/matrix-org/matrix-spec-proposals/pull/2246
[@maltee1]: https://github.com/maltee1
[#245]: https://github.com/mautrix/signal/pull/245

# v0.2.3 (2022-02-17)

Target signald version: [v0.17.0](https://gitlab.com/signald/signald/-/releases/0.17.0)

**N.B.** This will be the last release to support Python 3.7. Future versions
will require Python 3.8 or higher. In general, the mautrix bridges will only
support the lowest Python version in the latest Debian or Ubuntu LTS.

### Added
* New v2 link API to provide immediate feedback after the QR code is scanned.

### Improved
* Added automatic retrying for failed Matrix->Signal reactions.
* Commands using phone numbers will now try to resolve the UUID first
  (especially useful for `pm` so the portal is created with the correct ghost
  immediately)
* Improved signald socket handling to catch weird errors and reconnect.

### Fixed
* Fixed catching errors when connecting to Signal (e.g. if the account was
  deleted from signald's database, but not the bridge's).
* Fixed handling message deletions from Signal.
* Fixed race condition in incoming message deduplication.

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
