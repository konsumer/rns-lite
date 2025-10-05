This is a light implementation of reticulum, based on the [official python library](https://github.com/markqvist/Reticulum/).

This is a light "BYO" version that is compatable, but missing transport, interfaces, packet-callbacks, and file-use.

The essential idea is that is has utilities for the basics, but no automatic-management of things, and much smaller/simpler. The hope is that it will be usable in constrained enviroments, like micropython.

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
- onboard LED GPIO = 35

- load [esp32-s3 image](https://micropython.org/download/ESP32_GENERIC_S3/)

```sh
# install ESP32 CLI tools
pip install esptool

# install fresh micropython
esptool.py erase_flash
esptool.py --baud 460800 write_flash 0 ESP32_BOARD_NAME-DATE-VERSION.bin
```

To upload files:

```sh
# install ampy
pip install adafruit-ampy

# upload rns-lite
ampy --port /dev/tty.usbserial-0001 put rns.py

# upload test programs
ampy --port /dev/tty.usbserial-0001 put example_heltec_offline.py

# upload OLED driver
curl https://raw.githubusercontent.com/micropython/micropython-lib/refs/heads/master/micropython/drivers/display/ssd1306/ssd1306.py > /tmp/ssd1306.py
ampy --port /dev/tty.usbserial-0001 put /tmp/ssd1306.py

# upload radio driver
git clone https://github.com/git512/micropySX126X.git /tmp/micropySX126X
ampy --port /dev/tty.usbserial-0001 put /tmp/micropySX126X/lib/_sx126x.py
ampy --port /dev/tty.usbserial-0001 put /tmp/micropySX126X/lib/sx1262.py
ampy --port /dev/tty.usbserial-0001 put /tmp/micropySX126X/lib/sx126x.py

# upload msgpack
git clone https://github.com/peterhinch/micropython-msgpack.git /tmp/micropython-msgpack
ampy --port /dev/tty.usbserial-0001 put /tmp/micropython-msgpack/umsgpack
```

On mac/linux, I like to use picocom for my serial-terminal:

```sh
picocom -b115200 /dev/tty.usbserial-0001
```

You can close it with Ctrl-A, Ctrl-X. Now run an example:

```py
import example_heltec_offline
```

And you should see a decrypted message-packet on screen.
