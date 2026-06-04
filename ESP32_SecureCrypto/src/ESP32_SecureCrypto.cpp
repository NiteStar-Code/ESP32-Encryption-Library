#include "ESP32_SecureCrypto.h"


// ==========================================
// KeyHelperFunction
// ==========================================
void ESP32_SecureCrypto::hexToBytes(const char* hex, uint8_t* out, size_t keyLen = 32) {
    for (size_t i = 0; i < keyLen; i++) {
        auto h = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        out[i] = (h(hex[i*2]) << 4) | h(hex[i*2+1]);
    }
}

// ==========================================
// AES-GCM IMPLEMENTATION
// ==========================================

String ESP32_SecureCrypto::encryptAES(String data, const uint8_t* key) {
    size_t input_len = data.length();
    if (input_len == 0) return "";

    unsigned char iv[12];
    for(int i = 0; i < 12; i++) iv[i] = (unsigned char)random(0, 255);
    
    unsigned char* ciphertext = new unsigned char[input_len];
    unsigned char tag[16];

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, input_len, iv, 12, NULL, 0, 
                              (const unsigned char*)data.c_str(), ciphertext, 16, tag);

    String output = base64::encode(iv, 12) + ":" + 
                    base64::encode(tag, 16) + ":" + 
                    base64::encode(ciphertext, input_len);

    mbedtls_gcm_free(&gcm);
    delete[] ciphertext; 
    return output;
}

String ESP32_SecureCrypto::encryptAES(int value, const uint8_t* key) {
    return encryptAES(String(value), key);
}

String ESP32_SecureCrypto::decryptAES(String payload, const uint8_t* key) {
    int firstColon = payload.indexOf(':');
    int secondColon = payload.indexOf(':', firstColon + 1);
    
    if (firstColon == -1 || secondColon == -1) return "Error: Invalid Payload Format";

    String iv64 = payload.substring(0, firstColon);
    String tag64 = payload.substring(firstColon + 1, secondColon);
    String ct64 = payload.substring(secondColon + 1);

    unsigned char iv[12]; size_t iv_len;
    mbedtls_base64_decode(iv, sizeof(iv), &iv_len, (const unsigned char*)iv64.c_str(), iv64.length());

    unsigned char tag[16]; size_t tag_len;
    mbedtls_base64_decode(tag, sizeof(tag), &tag_len, (const unsigned char*)tag64.c_str(), tag64.length());

    size_t max_ct_len = ct64.length();
    unsigned char* ciphertext = new unsigned char[max_ct_len]; size_t ct_len;
    mbedtls_base64_decode(ciphertext, max_ct_len, &ct_len, (const unsigned char*)ct64.c_str(), ct64.length());

    unsigned char* plaintext = new unsigned char[ct_len + 1];
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    
    int ret = mbedtls_gcm_auth_decrypt(&gcm, ct_len, iv, 12, NULL, 0, tag, 16, ciphertext, plaintext);
    mbedtls_gcm_free(&gcm);

    String result = "";
    if (ret == 0) {
        plaintext[ct_len] = '\0';
        result = String((char*)plaintext);
    } else {
        result = "Decryption Failed! (Authentication Tag Mismatch)";
    }

    delete[] ciphertext;
    delete[] plaintext;
    return result;
}

// ==========================================
// XTEA IMPLEMENTATION
// ==========================================

void ESP32_SecureCrypto::xtea_block_encrypt(unsigned int num_rounds, uint8_t v[8], const uint8_t k[16]) {
    uint32_t v0 = ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16) | ((uint32_t)v[2] << 8) | v[3];
    uint32_t v1 = ((uint32_t)v[4] << 24) | ((uint32_t)v[5] << 16) | ((uint32_t)v[6] << 8) | v[7];
    
    uint32_t key[4];
    for (int i = 0; i < 4; i++) {
        key[i] = ((uint32_t)k[i*4] << 24) | ((uint32_t)k[i*4+1] << 16) | ((uint32_t)k[i*4+2] << 8) | k[i*4+3];
    }

    uint32_t sum = 0, delta = 0x9E3779B9;
    for (unsigned int i = 0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }

    v[0] = (v0 >> 24) & 0xFF; v[1] = (v0 >> 16) & 0xFF; v[2] = (v0 >> 8) & 0xFF; v[3] = v0 & 0xFF;
    v[4] = (v1 >> 24) & 0xFF; v[5] = (v1 >> 16) & 0xFF; v[6] = (v1 >> 8) & 0xFF; v[7] = v1 & 0xFF;
}

void ESP32_SecureCrypto::xtea_block_decrypt(unsigned int num_rounds, uint8_t v[8], const uint8_t k[16]) {
    uint32_t v0 = ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16) | ((uint32_t)v[2] << 8) | v[3];
    uint32_t v1 = ((uint32_t)v[4] << 24) | ((uint32_t)v[5] << 16) | ((uint32_t)v[6] << 8) | v[7];
    
    uint32_t key[4];
    for (int i = 0; i < 4; i++) {
        key[i] = ((uint32_t)k[i*4] << 24) | ((uint32_t)k[i*4+1] << 16) | ((uint32_t)k[i*4+2] << 8) | k[i*4+3];
    }

    uint32_t delta = 0x9E3779B9;
    uint32_t sum = delta * num_rounds;
    for (unsigned int i = 0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }

    v[0] = (v0 >> 24) & 0xFF; v[1] = (v0 >> 16) & 0xFF; v[2] = (v0 >> 8) & 0xFF; v[3] = v0 & 0xFF;
    v[4] = (v1 >> 24) & 0xFF; v[5] = (v1 >> 16) & 0xFF; v[6] = (v1 >> 8) & 0xFF; v[7] = v1 & 0xFF;
}

uint8_t ESP32_SecureCrypto::hex2bin(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

String ESP32_SecureCrypto::encryptXTEA(String plaintext, const uint8_t* key) {
    size_t orig_len = plaintext.length();
    size_t padded_len = ((orig_len + 7) / 8) * 8;
    
    uint8_t* padded_buffer = new uint8_t[padded_len];
    memset(padded_buffer, 0, padded_len);
    memcpy(padded_buffer, plaintext.c_str(), orig_len);

    uint8_t feedback[8];
    String hexOutput = "";
    char hexTemp[3];

    for(int i = 0; i < 8; i++) {
        feedback[i] = (uint8_t)esp_random();
        sprintf(hexTemp, "%02X", feedback[i]);
        hexOutput += hexTemp;
    }

    for (size_t i = 0; i < padded_len; i += 8) {
        uint8_t current_block[8];
        memcpy(current_block, padded_buffer + i, 8);

        for (int b = 0; b < 8; b++) {
            current_block[b] ^= feedback[b];
        }

        xtea_block_encrypt(32, current_block, key);

        for (int b = 0; b < 8; b++) {
            sprintf(hexTemp, "%02X", current_block[b]);
            hexOutput += hexTemp;
            feedback[b] = current_block[b];
        }
    }
    
    delete[] padded_buffer;
    return hexOutput;
}

String ESP32_SecureCrypto::encryptXTEA(int value, const uint8_t* key) {
    return encryptXTEA(String(value), key);
}

String ESP32_SecureCrypto::decryptXTEA(String hexInput, const uint8_t* key) {
    size_t hexLen = hexInput.length();
    if (hexLen < 16 || hexLen % 16 != 0) return "Error: Invalid payload length";

    size_t binLen = hexLen / 2;
    uint8_t* binData = new uint8_t[binLen];

    for(size_t i = 0; i < binLen; i++) {
        binData[i] = (hex2bin(hexInput[i*2]) << 4) | hex2bin(hexInput[i*2+1]);
    }

    uint8_t feedback[8];
    memcpy(feedback, binData, 8);

    size_t ctLen = binLen - 8;
    uint8_t* plaintext = new uint8_t[ctLen + 1];
    memset(plaintext, 0, ctLen + 1);

    for (size_t i = 0; i < ctLen; i += 8) {
        uint8_t current_block[8];
        uint8_t next_feedback[8];
        
        memcpy(current_block, binData + 8 + i, 8);
        memcpy(next_feedback, current_block, 8);

        xtea_block_decrypt(32, current_block, key);

        for(int b = 0; b < 8; b++) {
            current_block[b] ^= feedback[b];
        }

        memcpy(plaintext + i, current_block, 8);
        memcpy(feedback, next_feedback, 8);
    }

    String result = String((char*)plaintext);
    delete[] binData;
    delete[] plaintext;
    
    return result;
}
