#include <stdio.h>
#include <string.h>
#include "esp_system.h"
#include "esp_spi_flash.h"
#include "esp_log.h"
#include "mbedtls/base64.h"

void app_main(void) {
    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);

    char encoded_blob[128] = {0};
    spi_flash_read(0x10000, encoded_blob, sizeof(encoded_blob));

    char decoded[128] = {0};
    size_t len;
    mbedtls_base64_decode((unsigned char*)decoded, sizeof(decoded), &len,
                          (const unsigned char*)encoded_blob, strlen(encoded_blob));

    char expected[64];
    sprintf(expected, "AUTH::Moon::%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    if (strcmp(decoded, expected) == 0) {
        ESP_LOGI("BOOT", "Authentication successful. Booting main app...");
        esp_restart();
    } else {
        ESP_LOGE("BOOT", "Authentication failed. Halting.");
        while (1);
    }
}
