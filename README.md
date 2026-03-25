# sntrup761x25519sha512 KED with chacha20poly1305 AEAD -

## post quantum most secure server-client TCP communications initiation implementation that openSSH uses - 

### in rust with multithreaded async tokio server for quick and memory efficient comms with many clients at once

Written for SSH-like protocols to be written on top of


This is very far from being a protocol that u directly use for authenticated remote user filesystem executive access or anything, but one thing that is better in design in possible future ssh-like implementations:
    ssh server basically ignores the fact that CPU have more cores for practically decades now, when a new client starts a session it starts a new OS proccess, if for example 1000 people are connected to a same machine over it, that becomes massively inefficient, each process will just by existing take extra mbs of memory, making it full on impossible for thousands of clients to be connected to a same machine with an average memory over ssh.
    If the protocol directly handles all the connections to itself it could handle with far less of a memory layers of magnitude more connections at once.

