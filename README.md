This is a light implementation of reticulum, based on the [official python library](https://github.com/markqvist/Reticulum/).

This is a light "BYO" version that is compatable, but missing transport, interfaces, packet-callbacks, and file-use.

The essential idea is that is has utilities for the basics, but no automatic-management of things, and much smaller/simpler. The original hope was that it could be usable in constrained python enviroments, like micropython. I could not find a good way to get the crypto stuff working on micropython, though. It's either too slow (and has other problems like too much recursion) or there is an implementation in C, that I could not get to run (it requires a fuill recompile of micropython, and that worked, but boot-looped when I tried to run it.) I think my future-work on micros will be in C. Arduino has a lot of nice libraries, and it will run much better. This library still has a purpose though: simplicity. I can use it to more easily port other languages.

Also, check out:

- [nomadnet-js](https://github.com/konsumer/nomadnet-js) - for browser & node. Also includes [Websocket-interface](https://github.com/konsumer/nomadnet-js/blob/main/demo/interfaces/WebsocketClientInterface.py) & test-setup
- [reticulum-arduino](https://github.com/konsumer/reticulum-arduino)
- [cyd-nomad](https://github.com/konsumer/cyd-nomad)

```sh
# run unit-tests
pytest

# run demo echo-server
python examples/echobot.py
```
