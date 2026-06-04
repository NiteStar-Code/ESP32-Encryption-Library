#ifndef ESP32_SECURE_CRYPTO_H
#define ESP32_SECURE_CRYPTO_H

#include <Arduino.h>
#include <mbedtls/gcm.h>
#include <base64.h>
#include <mbedtls/base64.h>

class ESP32_SecureCrypto {
  public:
    //key functions
    static void hexToBytes(const char* hex, uint8_t* out, size_t keyLen);

    // AES-GCM 256
    static String encryptAES(String data, const uint8_t* key);
    static String encryptAES(int value, const uint8_t* key);
    static String decryptAES(String payload, const uint8_t* key);

    // XTEA
    static String encryptXTEA(String plaintext, const uint8_t* key);
    static String encryptXTEA(int value, const uint8_t* key);
    static String decryptXTEA(String hexInput, const uint8_t* key);

  private:
    // Internal Core Functions
    static void xtea_block_encrypt(unsigned int num_rounds, uint8_t v[8], const uint8_t k[16]);
    static void xtea_block_decrypt(unsigned int num_rounds, uint8_t v[8], const uint8_t k[16]);
    static uint8_t hex2bin(char c);
};

#endif
