# Features & roadmap

* Matrix → Signal
  * [ ] Message content
    * [x] Text
    * [ ] ‡Formatting
    * [ ] Media
      * [x] Images
      * [x] Audio files
      * [x] Files
      * [x] Gifs
      * [ ] Locations
      * [ ] Stickers
  * [x] Message reactions
  * [ ] Group info changes
    * [ ] Name
    * [ ] Avatar
  * [ ] Typing notifications
  * [ ] Read receipts
* Signal → Matrix
  * [ ] Message content
    * [x] Text
    * [ ] Media
      * [x] Images
      * [x] Voice notes
      * [x] Files
      * [x] Gifs
      * [ ] Contacts
      * [x] Locations
      * [x] Stickers
  * [x] Message reactions
  * [ ] Initial profile info
    * [x] User displayname
    * [ ] User avatar
    * [x] Group name
    * [ ] Group avatar
  * [ ] Profile info changes
    * [ ] User displayname
    * [ ] User avatar
    * [x] Group name
    * [ ] Group avatar
  * [ ] Typing notifications
  * [x] Read receipts
  * [ ] Disappearing messages
* Misc
  * [x] Automatic portal creation
    * [x] At startup
    * [x] When receiving message
  * [ ] Provisioning API for logging in
  * [ ] Private chat creation by inviting Matrix puppet of Signal user to new room
  * [ ] Option to use own Matrix account for messages sent from other Signal clients
    * [ ] Automatic login with shared secret
    * [ ] Manual login with `login-matrix`
  * [x] E2EE in Matrix rooms

† Not possible in signald  
‡ Not possible in Signal
