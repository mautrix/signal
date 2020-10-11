# mausignald
A Python/Asyncio library to communicate with [signald](https://gitlab.com/thefinn93/signald).

## Installation
TODO

## Usage
```python
import asyncio
from mausignald import SignaldClient
from mausignald.types import Message

client = SignaldClient()
username = "+1234567890"


async def qr_callback(uri: str) -> None:
  import os
  # This uses the qrencode cli tool for showing the QR code in the terminal
  # For proper apps, you might want to use the qrcode Python library to render an image instead.
  os.system(f"qrencode -t ansiutf8 '{uri}'")


async def handle_message(message: Message) -> None:
  # The Message event includes most things that happen in Signal, such as:
  # * messages from other users (message.data_message)
  # * typing notifications (message.typing)
  # * read receipts (message.receipt)
  # * messages synced from your other devices (message.sync_message.sent)
  # * read receipts synced from your other devices (message.sync_message.read_messages)

  print(f"Got message: {message}")
  if message.data_message:
    # This is a normal message from another user
    # Let's mark it as read
    await client.send_receipt(username, message.source, [message.data_message.timestamp], read=True)


async def main():
  # Event handlers should be added before connecting to make sure you don't miss anything
  client.add_event_handler(Message, handle_message)

  # Connect to the signald socket
  await client.connect()

  # If you haven't logged in yet, either
  # register:
  await client.register(username)
  sms_code = input("Enter SMS code:")
  await client.verify(username, sms_code)
  # or link:
  await client.link(qr_callback)

  # Always send a subscribe request when starting, otherwise you won't get messages
  await client.subscribe(username)

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
# The main function exits after it's done connecting/registering/subscribing,
# so tell the asyncio event loop to keep running anyway.
loop.run_forever()
```
