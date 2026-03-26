# sntrup761x25519sha512 KEM with chacha20poly1305 AEAD -

## post quantum most secure server-client TCP communications initiation implementation that openSSH uses - 

### in rust with multithreaded async tokio server for quick and memory efficient comms with many clients at once

Written for SSH-like protocols to be written on top of

<br>
This is very far from being a protocol that u directly use for authenticated remote user filesystem executive access or anything, but one thing that is better in design in possible future ssh-like implementations:
    ssh server basically ignores the fact that CPU have more cores for practically decades now, when a new client starts a session it starts a new OS proccess, if for example 1000 people are connected to a same machine over it, that becomes massively inefficient, each process will just by existing take extra mbs of memory, making it full on impossible for thousands of clients to be connected to a same machine with an average memory over ssh.
    If the protocol directly handles all the connections to itself it could handle with far less of a memory layers of magnitude more connections at once.


<br>

## current bin usages

Even tho this repo is mainly to be used as a jump off to protocol writing, when compiled it can be for running/testing the current sntrup761x25519sha512 and chacha20poly1305 implementation ran as a bin

To install the bin into ur /usr/bin do:
```bash
source dev_utils.sh
tldrify_and_install mate
```
then if u have a `tldr` on ur system u can also `tldr mate` to see the docs that will be also below

<br>

# mate

> post quantum most secure server-client TCP communications initiation implementation that openSSH uses in rust with parallel async server

- Just run as server

```bash
mate
```

- Choose a port on which ur server will run

```bash
mate 1024
```

- Server default runs on 0.0.0.0:<port>, so if ur firewall allows connection to that port, anyone on ur network (LAN unless you are port forwarding a public ip with the router or something) can mate 

<br>

- Run the server in a way so only ur local machine can mate the port

```bash
mate --localhost_only
```

`(can use any of             "--localhost", "--localhost_only", "--localhostonly", "--local", "--localonly", "--local_only"         variations because I am autistic)`


<br>
<br>

- Run as a client just by running `@` in the query with the IP:port

```bash
mate @10.0.0.2:1024
```

- Using with no extra flags the client and server will only mate via sntrup761x25519sha512 in different words the client and server will only do the KEM (key encapsulation mechanism) so they both independently derive a shared secret key for further communications but will not yet use it for anything

<br>

- Run as client to only mate with a mate server running on localhost

```bash
mate @1024
```

<br>

- Do the KEM mating and afterwards use the shared secret to encrypt a message with the chacha20poly1305 algorithm and send it to the server so the terminal running the server just decrypts and prints the mesage

```bash
mate @10.0.0.2:1024 --mess_test_without_auth "hello batman!"
```

`(again can use the flag in any of          "--mess_test_without_auth", "--messtestwithoutauth", "messagetestwithoutauth", "--message_test_without_auth"             ways because my weird needs)`


<br>
<br>
This has only the KEM and sending a message implemented, to further implement a full on networking protocol to use for for example executive access u should obviously also implement authentication, sntrup761x25519sha512 KEM with chacha20poly1305 is just the method used so a client and server can establish a post quantum shared secret in which they are to initiate any encrypted communications that will be at each session initialized with each time newly generated shared secret.

<br>
<br>

Docs for sntrup761x25519sha512 are something u have to google (or ask an llm) separately, I won't repeat a documentation work that is already done on the internet, but the latex math in the repo might help u in getting it

<br>

https://www.ietf.org/archive/id/draft-josefsson-ntruprime-ssh-02.html might explain it a little to u, but to be real with u an llm will explain it far better to u with all nuances and so u actually know what the flip it does and why


<br>
<br>
It is not dangerous or anything to run this server on a public ip or whatever, as u read from the docs this is but a mating protocol (that should be used as a first step in a protocol), where the worst someone can remotely do to your server is send a 255 max char message to u that ur server terminal will print to the screen (escape chars not allowed - if someone tries to send a message that has escape chars that message will not even get passed to the println!)

<br>

Sorry for bad grammar in docs, not into that stuff

