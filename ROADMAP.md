# Features & roadmap

* Matrix → Signal
  * [ ] Message content
    * [x] Text
    * [x] Formatting
    * [x] Mentions
    * [ ] Media
      * [x] Images
      * [x] Audio files
      * [x] Voice messages
      * [x] Files
      * [x] Gifs
      * [ ] Locations
      * [x] Stickers
  * [x] Message reactions
  * [x] Message redactions
  * [ ] Group info changes
    * [ ] Name
    * [ ] Avatar
    * [ ] Topic
  * [ ] Membership actions
    * [ ] Join (accepting invites)
    * [ ] Invite
    * [ ] Leave
    * [ ] Kick/Ban/Unban
  * [x] Typing notifications
  * [ ] Read receipts (currently partial support, only marks last message)
  * [x] Delivery receipts (sent after message is bridged)
* Signal → Matrix
  * [x] Message content
    * [x] Text
    * [x] Formatting
    * [x] Mentions
    * [x] Media
      * [x] Images
      * [x] Voice notes
      * [x] Files
      * [x] Gifs
      * [x] Contacts
      * [x] Stickers
  * [x] Message reactions
  * [x] Remote deletions
  * [x] Initial profile/contact info
  * [ ] Profile/contact info changes
    * [x] When restarting bridge or syncing
    * [ ] Real time
  * [x] Group info
    * [x] Name
    * [x] Avatar
    * [x] Topic
  * [ ] Membership actions
    * [ ] Join
    * [ ] Invite
    * [ ] Request join (via invite link, requires a client that supports knocks)
    * [ ] Leave
    * [ ] Kick/Ban/Unban
  * [ ] Group permissions
  * [x] Typing notifications
  * [x] Read receipts
  * [ ] Delivery receipts (there's no good way to bridge these)
  * [x] Disappearing messages
* Misc
  * [ ] Automatic portal creation
    * [ ] After login
    * [x] When receiving message
  * [x] Linking as secondary device
  * [ ] Registering as primary device
  * [x] Private chat/group creation by inviting Matrix puppet of Signal user to new room
  * [x] Option to use own Matrix account for messages sent from other Signal clients
