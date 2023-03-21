# Features & roadmap

* Matrix → Signal
  * [ ] Message content
    * [ ] Text
    * [ ] ‡Formatting
    * [ ] Mentions
    * [ ] Media
      * [ ] Images
      * [ ] Audio files
      * [ ] Files
      * [ ] Gifs
      * [ ] Locations
      * [ ] Stickers
  * [ ] Message reactions
  * [ ] Message redactions
  * [ ] Group info changes
    * [ ] Name
    * [ ] Avatar
  * [ ] Membership actions
    * [ ] Join (accept invite)
    * [ ] Invite
    * [ ] Leave
    * [ ] Kick/Ban/Unban
  * [ ] Typing notifications
  * [ ] Read receipts (currently partial support, only marks last message)
  * [ ] Delivery receipts (sent after message is bridged)
* Signal → Matrix
  * [ ] Message content
    * [ ] Text
    * [ ] Mentions
    * [ ] Media
      * [ ] Images
      * [ ] Voice notes
      * [ ] Files
      * [ ] Gifs
      * [ ] Contacts
      * [ ] Locations
      * [ ] Stickers
  * [ ] Message reactions
  * [ ] Remote deletions
  * [ ] Initial user and group profile info
  * [ ] Profile info changes
    * [ ] When restarting bridge or syncing
    * [ ] Real time
      * [ ] Groups
      * [ ] Users
  * [ ] Membership actions
    * [ ] Join
    * [ ] Invite
    * [ ] Request join (via invite link, requires a client that supports knocks)
    * [ ] Leave
    * [ ] Kick/Ban/Unban
  * [ ] Group permissions
  * [ ] Typing notifications
  * [ ] Read receipts
  * [ ] Delivery receipts (there's no good way to bridge these)
  * [ ] Disappearing messages
* Misc
  * [ ] Automatic portal creation
    * [ ] At startup
    * [ ] When receiving message
  * [ ] Provisioning API for logging in
    * [ ] Linking as secondary device
    * [ ] Registering as primary device
  * [ ] Private chat/group creation by inviting Matrix puppet of Signal user to new room
  * [ ] Option to use own Matrix account for messages sent from other Signal clients
    * [ ] Automatic login with shared secret
    * [ ] Manual login with `login-matrix`
  * [ ] E2EE in Matrix rooms

‡ Not possible in Signal
