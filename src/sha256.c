#include "../includes/signer.h"

#include <stdio.h>

#include <openssl/evp.h>

#define SIGNER_HASH_BUFFER_SIZE 65536

int signer_sha256_file(
    const char *path,
    char output[SIGNER_SHA256_HEX_LENGTH + 1]
)
{
    FILE *file = NULL;
    EVP_MD_CTX *context = NULL;

    unsigned char buffer[SIGNER_HASH_BUFFER_SIZE];
    unsigned char digest[EVP_MAX_MD_SIZE];

    unsigned int digest_length = 0;
    size_t bytes_read;
    size_t i;

    static const char hex[] = "0123456789abcdef";

    if (path == NULL || output == NULL) {
        return 0;
    }

    output[0] = '\0';

    file = fopen(path, "rb");

    if (file == NULL) {
        fprintf(
            stderr,
            "[FAIL] Could not open package: %s\n",
            path
        );

        return 0;
    }

    context = EVP_MD_CTX_new();

    if (context == NULL) {
        fprintf(
            stderr,
            "[FAIL] Could not initialize SHA-256 context.\n"
        );

        fclose(file);
        return 0;
    }

    if (EVP_DigestInit_ex(
            context,
            EVP_sha256(),
            NULL
        ) != 1) {
        fprintf(
            stderr,
            "[FAIL] Could not initialize SHA-256 calculation.\n"
        );

        goto cleanup;
    }

    while ((bytes_read = fread(
                buffer,
                1,
                sizeof(buffer),
                file
            )) > 0) {
        if (EVP_DigestUpdate(
                context,
                buffer,
                bytes_read
            ) != 1) {
            fprintf(
                stderr,
                "[FAIL] SHA-256 calculation failed.\n"
            );

            goto cleanup;
        }
    }

    if (ferror(file)) {
        fprintf(
            stderr,
            "[FAIL] Could not completely read package: %s\n",
            path
        );

        goto cleanup;
    }

    if (EVP_DigestFinal_ex(
            context,
            digest,
            &digest_length
        ) != 1) {
        fprintf(
            stderr,
            "[FAIL] Could not finalize SHA-256 calculation.\n"
        );

        goto cleanup;
    }

    if (digest_length != 32) {
        fprintf(
            stderr,
            "[FAIL] Unexpected SHA-256 digest length.\n"
        );

        goto cleanup;
    }

    for (i = 0; i < digest_length; ++i) {
        output[i * 2] =
            hex[(digest[i] >> 4) & 0x0f];

        output[(i * 2) + 1] =
            hex[digest[i] & 0x0f];
    }

    output[SIGNER_SHA256_HEX_LENGTH] = '\0';

    EVP_MD_CTX_free(context);
    fclose(file);

    return 1;

cleanup:
    output[0] = '\0';

    EVP_MD_CTX_free(context);
    fclose(file);

    return 0;
}