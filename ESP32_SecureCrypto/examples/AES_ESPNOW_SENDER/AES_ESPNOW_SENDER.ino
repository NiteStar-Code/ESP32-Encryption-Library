#include <ESP32_SecureCrypto.h>

const char* key; //Paste raw text key here
uint8_t aes_key[32];

void setup() {
  Serial.begin(115200);
  ESP32_SecureCrypto::hexToBytes(key, aes_key);
}

void loop() {
  int randomValue = random(1, 100);
  String encryptedPayload = ESP32_SecureCrypto::encryptAES(randomValue, aes_key);
  Serial.println("Random Number: " + String(randomValue) + " Encrypted Payload: " + encryptedPayload);
  delay(2000);
}