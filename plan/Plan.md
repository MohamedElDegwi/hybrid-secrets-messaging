## Project Title
Hybrid messaging server

## Project Details
This is a terminal based messaging server that acts as a chat group for clients or for better callings, local IRC

* new clients can register via open new tab.
* clients must set their username and nickname before connecting to the server.
* server is up and listen to some static predefined socket.
* clients can send their messages to the server and its server duty to distribute those messages to all connected users.
* server must be smart enough to not send the message again to the sender.
* all messages must be fully encrypted before they reach the server and decrypted on the client side with some crypto mechanism
* add a debugger that acts as "spoofer" that sniffs on the open socket try to sneak peek on messages.
* spoofer should see garbage data as well as server both should have no idea about the actual message content.
* spoofer could be simple C program that listen to the same socket but "silently".

## Ideas to discuss
this above functionality is the core, but there is some nice to have ideas that i would love to hear your voice on.

* should server have a context of connecting and disconnecting time of each registered user? 
    the benefit of this is server can send all send messages to users that got send when they were away but that is optional.

## Suggested programming languages.
    C -> to manage the local relay server.
    Rust + OpenSSL -> to manage the cryptographic operations.
    