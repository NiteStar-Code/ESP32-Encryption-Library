# ESP32-Encryption-Libray

## Instructions on adding to Arduino IDE
Clone the git hub repo
Zip the ESP32_SecureCrypto
Install the library in Arduino IDE

## Instructions for encryption
Include ESP32_SecureCrypto.h header file
Key must be in bytes format. In case of text format use hexToBytes() function (look in the examples folder)
While converting text to bytes using hexToBytes() function, last argument should be 32 (for 32 byte key)

## Instructions for decryption
In case of decryption, replace the key in dc.py with your key

## Types of encryptions
As of right now these are the following encryptions/decryptions available
# AES (complex but secure)
- encryptAES
- decryptAES

# XTEA (less complex, less secure)
- encryptXTEA
- decryptXTEA
