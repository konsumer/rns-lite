from machine import SoftI2C, Pin
import ssd1306
import time

white_led = Pin(35, Pin.OUT) 
oled_rst_pin = Pin(21, Pin.OUT, value=1)
oled_sda_pin=Pin(17, Pin.OPEN_DRAIN)
oled_scl_pin=Pin(18, Pin.OPEN_DRAIN)
oled_rst_pin=Pin(21, Pin.OUT, value=1)
i2c=SoftI2C(sda=oled_sda_pin, scl=oled_scl_pin)
oled_sda_pin.init(Pin.OPEN_DRAIN, pull=Pin.PULL_UP)
oled_scl_pin.init(Pin.OPEN_DRAIN, pull=Pin.PULL_UP)

scan_result = i2c.scan()
if len(scan_result) == 1:
    print(f"OLED I2C device found at {hex(scan_result[0])}")

display = ssd1306.SSD1306_I2C(128, 64, i2c, addr=0x3C, external_vcc=False)

backlight_pin.value(0)

display.fill(0)
display.text("Display I2C" , 0, 22, 1)
display.text(f"address: {hex(int(scan_result[0]))}", 0, 38, 1)
display.show()

time.sleep(5)
backlight_pin.value(1)

for i in range(2):
    white_led.value(1)
    time.sleep(0.2)
    white_led.value(0)
    time.sleep(0.2)



