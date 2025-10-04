This is a light implementation of reticulum, based on the [official python library](https://github.com/markqvist/Reticulum/).

This is a light "BYO" version that is compatable, but missing transport, interfaces, packet-callbacks, and file-use.

The essential idea is that is has the basics, and works the same, but no automatic-management of things. The hope is that it will be usable in constrained enviroments, like micropython, but still feel familiar.

You can just not use that stuff, but eventuallly I will strip it all out. For now, this is mostly a code-style thing, and you should be able to run all the same code in multiple pyhton runtimes & environments, including cpython + normal RNS. 


## how to use this on Heltec v3

I started with a Heltec v3. It should work great on other things, but that is what I had on-hand that already had a lora radio attached, for testing.

### hardware

screen io:
- scl pin is 18
- sda pin is 17
- reset = 21 (must stay high to write to it)
- backlight = 36

radio io:
- chip is SX1262: [uPy lib for chip](https://github.com/git512/micropySX126X)

chip pins
- SS (CS)= 8
- SCK (CLK)= 9
- MOSI = 10
- MISO = 11
- RST = 12
- BUSY = 13
- DIO (also irq) = 14
- onboard GPIO = 35


- load [esp32-s3 image](https://micropython.org/download/ESP32_GENERIC_S3/)

```
esptool.py erase_flash
esptool.py --baud 460800 write_flash 0 ESP32_BOARD_NAME-DATE-VERSION.bin
```

Now, put RNS in /libraries, heltec_offline.py & test/demo_data.py in /. run it with "import heltec_offline" in REPL, you should see output on screen.