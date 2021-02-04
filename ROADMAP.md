# Features & roadmap

* Matrix → Signal
  * [ ] Message content
    * [x] Text
    * [ ] ‡Formatting
    * [ ] Mentions
    * [ ] Media
      * [x] Images
      * [x] Audio files
      * [x] Files
      * [x] Gifs
      * [ ] Locations
      * [ ] Stickers
  * [x] Message reactions
  * [ ] Message redactions
  * [ ] Group info changes
    * [ ] Name
    * [ ] Avatar
  * [ ] †Typing notifications
  * [ ] Read receipts (currently partial support, only marks last message)
  * [x] Delivery receipts (sent after message is bridged)
* Signal → Matrix
  * [ ] Message content
    * [x] Text
    * [ ] Mentions
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
  * [ ] Initial profile info
    * [x] User displayname
    * [x] User avatar
    * [x] Group name
    * [ ] †Group avatar
  * [ ] Profile info changes
    * [ ] User displayname
    * [ ] †User avatar
    * [x] Group name
    * [x] Group avatar
  * [x] Typing notifications
  * [x] Read receipts
  * [ ] Delivery receipts (there's no good way to bridge these)
  * [ ] Disappearing messages
* Misc
  * [x] Automatic portal creation
    * [x] At startup
    * [x] When receiving message
      * [ ] in v2 groups
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
