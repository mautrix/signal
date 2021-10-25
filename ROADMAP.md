# Features & roadmap

* Matrix → Signal
  * [ ] Message content
    * [x] Text
    * [ ] ‡Formatting
    * [x] Mentions
    * [ ] Media
      * [x] Images
      * [x] Audio files
      * [x] Files
      * [x] Gifs
      * [ ] Locations
      * [ ] Stickers
  * [x] Message reactions
  * [x] Message redactions
  * [x] Group info changes
    * [x] Name
    * [x] Avatar
  * [ ] Membership actions
    * [x] Join (accept invite)
    * [ ] Invite
    * [ ] Leave
    * [ ] Kick
  * [ ] Typing notifications
  * [ ] Read receipts (currently partial support, only marks last message)
  * [x] Delivery receipts (sent after message is bridged)
* Signal → Matrix
  * [ ] Message content
    * [x] Text
    * [x] Mentions
    * [ ] Media
      * [x] Images
      * [x] Voice notes
      * [x] Files
      * [x] Gifs
      * [ ] Contacts
      * [x] Locations
      * [x] Stickers
  * [x] Message reactions
  * [x] Remote deletions
  * [x] Initial user and group profile info
  * [ ] Profile info changes
    * [x] When restarting bridge or syncing
    * [ ] Real time
      * [x] Groups
      * [ ] Users
  * [ ] Membership actions
    * [x] Join
    * [x] Invite
    * [ ] Request join (via invite link)
    * [ ] Kick / leave
  * [x] Group permissions
  * [x] Typing notifications
  * [x] Read receipts
  * [ ] Delivery receipts (there's no good way to bridge these)
  * [ ] Disappearing messages
* Misc
  * [x] Automatic portal creation
    * [x] At startup
    * [x] When receiving message
  * [ ] Provisioning API for logging in
    * [x] Linking as secondary device
    * [ ] Registering as primary device
  * [ ] Private chat creation by inviting Matrix puppet of Signal user to new room
  * [x] Option to use own Matrix account for messages sent from other Signal clients
    * [x] Automatic login with shared secret
    * [x] Manual login with `login-matrix`
  * [x] E2EE in Matrix rooms

† Not possible in signald  
‡ Not possible in Signal
