#include "../includes/signer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

static EVP_PKEY *load_private_key(void)
{
    FILE *file;
    EVP_PKEY *key;

    file = fopen(SIGNER_PRIVATE_KEY_FILE, "rb");
    if (file == NULL) {
        return NULL;
    }

    key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);

    return key;
}

static EVP_PKEY *load_public_key(void)
{
    FILE *file;
    EVP_PKEY *key;

    file = fopen(SIGNER_PUBLIC_KEY_FILE, "rb");
    if (file == NULL) {
        return NULL;
    }

    key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);

    return key;
}

static char *base64_encode(
    const unsigned char *input,
    size_t input_length
)
{
    char *output;
    size_t output_length;

    if (input == NULL || input_length == 0) {
        return NULL;
    }

    output_length = 4 * ((input_length + 2) / 3);

    output = malloc(output_length + 1);
    if (output == NULL) {
        return NULL;
    }

    if (EVP_EncodeBlock(
            (unsigned char *)output,
            input,
            (int)input_length
        ) < 0) {
        free(output);
        return NULL;
    }

    output[output_length] = '\0';
    return output;
}

static char *json_escape(const char *input)
{
    const unsigned char *cursor;
    char *output;
    char *writer;
    size_t length = 0;

    if (input == NULL) {
        return NULL;
    }

    for (cursor = (const unsigned char *)input; *cursor != '\0'; ++cursor) {
        switch (*cursor) {
            case '"':
            case '\\':
                length += 2;
                break;

            case '\b':
            case '\f':
            case '\n':
            case '\r':
            case '\t':
                length += 2;
                break;

            default:
                if (*cursor < 0x20) {
                    length += 6;
                } else {
                    length += 1;
                }
                break;
        }
    }

    output = malloc(length + 1);
    if (output == NULL) {
        return NULL;
    }

    writer = output;

    for (cursor = (const unsigned char *)input; *cursor != '\0'; ++cursor) {
        switch (*cursor) {
            case '"':
                *writer++ = '\\';
                *writer++ = '"';
                break;

            case '\\':
                *writer++ = '\\';
                *writer++ = '\\';
                break;

            case '\b':
                *writer++ = '\\';
                *writer++ = 'b';
                break;

            case '\f':
                *writer++ = '\\';
                *writer++ = 'f';
                break;

            case '\n':
                *writer++ = '\\';
                *writer++ = 'n';
                break;

            case '\r':
                *writer++ = '\\';
                *writer++ = 'r';
                break;

            case '\t':
                *writer++ = '\\';
                *writer++ = 't';
                break;

            default:
                if (*cursor < 0x20) {
                    static const char hex[] = "0123456789abcdef";

                    *writer++ = '\\';
                    *writer++ = 'u';
                    *writer++ = '0';
                    *writer++ = '0';
                    *writer++ = hex[(*cursor >> 4) & 0x0f];
                    *writer++ = hex[*cursor & 0x0f];
                } else {
                    *writer++ = (char)*cursor;
                }
                break;
        }
    }

    *writer = '\0';
    return output;
}

char *signer_release_statement(
    const release_info *release,
    const signer_identity *identity
)
{
    static const char format[] =
        "CHAOS-MVC-MODULE-RELEASE\n"
        "module=%s\n"
        "version=%s\n"
        "download=%s\n"
        "sha256=%s\n"
        "key_id=%s";

    int required;
    char *statement;

    if (release == NULL
        || identity == NULL
        || release->module == NULL
        || release->version == NULL
        || release->download_url == NULL
        || release->sha256[0] == '\0'
        || identity->key_id[0] == '\0') {
        return NULL;
    }

    required = snprintf(
        NULL,
        0,
        format,
        release->module,
        release->version,
        release->download_url,
        release->sha256,
        identity->key_id
    );

    if (required < 0) {
        return NULL;
    }

    statement = malloc((size_t)required + 1);
    if (statement == NULL) {
        return NULL;
    }

    if (snprintf(
            statement,
            (size_t)required + 1,
            format,
            release->module,
            release->version,
            release->download_url,
            release->sha256,
            identity->key_id
        ) != required) {
        free(statement);
        return NULL;
    }

    return statement;
}

char *signer_release_sign_and_verify(const char *statement)
{
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;
    EVP_MD_CTX *sign_context = NULL;
    EVP_MD_CTX *verify_context = NULL;

    unsigned char *signature = NULL;
    size_t signature_length = 0;

    char *encoded_signature = NULL;

    if (statement == NULL || statement[0] == '\0') {
        return NULL;
    }

    private_key = load_private_key();
    public_key = load_public_key();

    if (private_key == NULL || public_key == NULL) {
        fprintf(
            stderr,
            "[FAIL] Signing identity could not be loaded.\n"
        );

        goto cleanup;
    }

    sign_context = EVP_MD_CTX_new();
    verify_context = EVP_MD_CTX_new();

    if (sign_context == NULL || verify_context == NULL) {
        fprintf(
            stderr,
            "[FAIL] Could not initialize signing contexts.\n"
        );

        goto cleanup;
    }

    if (EVP_DigestSignInit(
            sign_context,
            NULL,
            EVP_sha256(),
            NULL,
            private_key
        ) <= 0) {
        fprintf(
            stderr,
            "[FAIL] Could not initialize RSA/SHA-256 signing.\n"
        );

        goto cleanup;
    }

    if (EVP_DigestSignUpdate(
            sign_context,
            statement,
            strlen(statement)
        ) <= 0) {
        fprintf(
            stderr,
            "[FAIL] Could not process canonical release statement.\n"
        );

        goto cleanup;
    }

    if (EVP_DigestSignFinal(
            sign_context,
            NULL,
            &signature_length
        ) <= 0) {
        fprintf(
            stderr,
            "[FAIL] Could not determine signature size.\n"
        );

        goto cleanup;
    }

    signature = OPENSSL_malloc(signature_length);
    if (signature == NULL) {
        fprintf(
            stderr,
            "[FAIL] Could not allocate signature buffer.\n"
        );

        goto cleanup;
    }

    if (EVP_DigestSignFinal(
            sign_context,
            signature,
            &signature_length
        ) <= 0) {
        fprintf(
            stderr,
            "[FAIL] RSA/SHA-256 signing failed.\n"
        );

        goto cleanup;
    }

    printf("[PASS] Release signed with RSA/SHA-256.\n");

    if (EVP_DigestVerifyInit(
            verify_context,
            NULL,
            EVP_sha256(),
            NULL,
            public_key
        ) <= 0) {
        fprintf(
            stderr,
            "[FAIL] Could not initialize signature verification.\n"
        );

        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(
            verify_context,
            statement,
            strlen(statement)
        ) <= 0) {
        fprintf(
            stderr,
            "[FAIL] Could not process verification statement.\n"
        );

        goto cleanup;
    }

    if (EVP_DigestVerifyFinal(
            verify_context,
            signature,
            signature_length
        ) != 1) {
        fprintf(
            stderr,
            "[FAIL] Release signature verification failed.\n"
        );

        goto cleanup;
    }

    printf("[PASS] Release signature independently verified.\n");

    encoded_signature = base64_encode(
        signature,
        signature_length
    );

    if (encoded_signature == NULL) {
        fprintf(
            stderr,
            "[FAIL] Could not Base64 encode verified signature.\n"
        );
    }

cleanup:
    OPENSSL_free(signature);

    EVP_MD_CTX_free(sign_context);
    EVP_MD_CTX_free(verify_context);

    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);

    return encoded_signature;
}

int signer_manifest_write(
    const release_info *release,
    const signer_identity *identity,
    const char *signature
)
{
    FILE *file = NULL;

    char *module = NULL;
    char *version = NULL;
    char *download = NULL;
    char *key_id = NULL;
    char *encoded_signature = NULL;

    int result = 0;

    if (release == NULL
        || identity == NULL
        || signature == NULL
        || signature[0] == '\0') {
        return 0;
    }

    module = json_escape(release->module);
    version = json_escape(release->version);
    download = json_escape(release->download_url);
    key_id = json_escape(identity->key_id);
    encoded_signature = json_escape(signature);

    if (module == NULL
        || version == NULL
        || download == NULL
        || key_id == NULL
        || encoded_signature == NULL) {
        fprintf(
            stderr,
            "[FAIL] Could not prepare manifest fields.\n"
        );

        goto cleanup;
    }

    file = fopen(SIGNER_MANIFEST_FILE, "wb");
    if (file == NULL) {
        fprintf(
            stderr,
            "[FAIL] Could not write %s.\n",
            SIGNER_MANIFEST_FILE
        );

        goto cleanup;
    }

    if (fprintf(
            file,
            "{\n"
            "    \"module\": \"%s\",\n"
            "    \"version\": \"%s\",\n"
            "    \"download\": \"%s\",\n"
            "    \"sha256\": \"%s\",\n"
            "    \"key_id\": \"%s\",\n"
            "    \"signature\": \"%s\"\n"
            "}\n",
            module,
            version,
            download,
            release->sha256,
            key_id,
            encoded_signature
        ) < 0) {
        fprintf(
            stderr,
            "[FAIL] Could not complete %s.\n",
            SIGNER_MANIFEST_FILE
        );

        fclose(file);
        file = NULL;

        remove(SIGNER_MANIFEST_FILE);
        goto cleanup;
    }

    if (fclose(file) != 0) {
        file = NULL;

        fprintf(
            stderr,
            "[FAIL] Could not finalize %s.\n",
            SIGNER_MANIFEST_FILE
        );

        remove(SIGNER_MANIFEST_FILE);
        goto cleanup;
    }

    file = NULL;

    printf(
        "[PASS] %s written.\n",
        SIGNER_MANIFEST_FILE
    );

    result = 1;

cleanup:
    if (file != NULL) {
        fclose(file);
    }

    free(module);
    free(version);
    free(download);
    free(key_id);
    free(encoded_signature);

    return result;
}
