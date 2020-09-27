# Features & roadmap

* Matrix → Signal
  * [ ] Message content
    * [x] Text
    * [ ] ‡Formatting
    * [ ] Media
      * [ ] Images
      * [ ] Files
      * [ ] Gifs
      * [ ] Locations
      * [ ] †Stickers
  * [x] Message reactions
  * [ ] Typing notifications
  * [ ] Read receipts
* Signal → Matrix
  * [ ] Message content
    * [x] Text
    * [ ] Media
      * [ ] Images
      * [ ] Files
      * [ ] Gifs
      * [ ] Contacts
      * [ ] Locations
      * [ ] Stickers
  * [x] Message reactions
  * [ ] †User and group avatars
  * [ ] Typing notifications
  * [x] Read receipts
  * [ ] Disappearing messages
* Misc
  * [x] Automatic portal creation
    * [x] At startup
    * [ ] When receiving message
  * [ ] Provisioning API for logging in
  * [ ] Private chat creation by inviting Matrix puppet of Signal user to new room
  * [ ] Option to use own Matrix account for messages sent from other Signal clients
    * [ ] Automatic login with shared secret
    * [ ] Manual login with `login-matrix`
  * [x] E2EE in Matrix rooms

† Not possible in signald
‡ Not possible in Signal
