# parse & decrypt a reticulum DATA pacaket, offline, on a Heltec v3

from machine import SoftI2C, Pin
import ssd1306
import rns
from umsgpack import unpackb

pin_led_white = Pin(35, Pin.OUT)
pin_backlight = Pin(36, Pin.OUT)
pin_sda = Pin(17, Pin.OPEN_DRAIN)
pin_scl = Pin(18, Pin.OPEN_DRAIN)
pin_sda.init(Pin.OPEN_DRAIN, pull=Pin.PULL_UP)
pin_scl.init(Pin.OPEN_DRAIN, pull=Pin.PULL_UP)
i2c = SoftI2C(sda=pin_sda, scl=pin_scl)
display = ssd1306.SSD1306_I2C(128, 64, i2c, addr=0x3C, external_vcc=False)

# a DATA packet from 072ec44973a8dee8e28d230fb4af8fe4 to 76a93cda889a8c0a88451e02d53fd8b9
pin_led_white.value(0)
packet = rns.decode_packet(
    bytes.fromhex(
        "000076a93cda889a8c0a88451e02d53fd8b900f549cccf8d574cb520c8f12ea6ea67c4f4ce34f301de611cd942acbfb6933f3f7a025d5b6d6184d04dd0279b8037f1c9c1c1c25defbdd5e62aa8fb04502101014a501b9235e62f823bbdfd4d85e7656d765802f115a01b57b823ae02cc94899ae3a0f94bf7c32f1a73c027e5c95e0dd94c72c833ea75951af517da665eff26bca45e90e2eaa18775e65799ea0b3a977645107850dbfe62bb1f3228b50ac6e775006c4f18d6f3a1474233dc9b13cd95f6a6f581ad0b85de7196ea606d393d35f1"
    )
)
pin_led_white.value(1)

# the ratchet-private (derived from public) keys for both (normally each would have 1 of these)
ratchets = [
    bytes.fromhex("205cb256c44d4d3939bdc02e2a9667de4214cbcc651bbdc0a318acf7ec68b066"),
    bytes.fromhex("28dd4da561a9bc0cb7d644a4487c01cbe32b01718a21f18905f5611b110a5c45"),
]

# the private key of the receiver (encrypt/sign, 32 bytes each)
identity = bytes.fromhex(
    "e8c5c096166f3554868de9133b0c55c7abf0318230860a142ea3f84a0aae7759142f6c0b84d9f537ceb2e8e9678fc9fb77caf91e2176278fb4c4f5c3eb7b48cd"
)

pin_led_white.value(0)
decrypted = rns.decode_data(packet, identity, ratchets=ratchets)
pin_led_white.value(1)

# LXMF messages are msgpacked
decoded = unpackb(decrypted)

pin_backlight.value(0)
display.fill(0)
display.text(f"TEST", 0, 0, 1)
display.show()
