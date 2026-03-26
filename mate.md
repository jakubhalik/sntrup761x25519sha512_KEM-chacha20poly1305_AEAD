# mate

> post quantum most secure server-client TCP communications initiation implementation that openSSH uses in rust with parallel async server

- Just run as server

`mate`

- Choose a port on which ur server will run

`mate 1024`

- Server default runs on 0.0.0.0:<port>, so if ur firewall allows connection to that port, anyone on ur network (LAN unless you are port forwarding a public ip with the router or something) can mate 

- Run the server in a way so only ur local machine can mate the port

`mate --localhost_only`


`(can use any of             "--localhost", "--localhost_only", "--localhostonly", "--local", "--localonly", "--local_only"         variations because I am autistic)`



- Run as a client just by running `@` in the query with the IP:port

`mate @10.0.0.2:1024`

- Using with no extra flags the client and server will only mate via sntrup761x25519sha512 in different words the client and server will only do the KEM (key encapsulation mechanism) so they both independently derive a shared secret key for further communications but will not yet use it for anything


- Run as client to only mate with a mate server running on localhost

`mate @1024`


- Do the KEM mating and afterwards use the shared secret to encrypt a message with the chacha20poly1305 algorithm and send it to the server so the terminal running the server just decrypts and prints the mesage

`mate @10.0.0.2:1024 --mess_test_without_auth "hello batman!"`


`(again can use the flag in any of          "--mess_test_without_auth", "--messtestwithoutauth", "messagetestwithoutauth", "--message_test_without_auth"             ways because my weird needs)`

