#include "../includes/signer.h"

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

static int file_exists(const char *path)
{
    FILE *file = fopen(path, "rb");

    if (file == NULL) {
        return 0;
    }

    fclose(file);
    return 1;
}

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

static int write_private_key(EVP_PKEY *key)
{
    FILE *file;
    int result;

    file = fopen(SIGNER_PRIVATE_KEY_FILE, "wb");
    if (file == NULL) {
        return 0;
    }

    result = PEM_write_PrivateKey(
        file,
        key,
        NULL,
        NULL,
        0,
        NULL,
        NULL
    );

    fclose(file);

    return result == 1;
}

static int write_public_key(EVP_PKEY *key)
{
    FILE *file;
    int result;

    file = fopen(SIGNER_PUBLIC_KEY_FILE, "wb");
    if (file == NULL) {
        return 0;
    }

    result = PEM_write_PUBKEY(file, key);
    fclose(file);

    return result == 1;
}

static EVP_PKEY *generate_private_key(void)
{
    EVP_PKEY_CTX *context;
    EVP_PKEY *key = NULL;

    context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (context == NULL) {
        return NULL;
    }

    if (EVP_PKEY_keygen_init(context) <= 0) {
        EVP_PKEY_CTX_free(context);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(
            context,
            SIGNER_RSA_BITS
        ) <= 0) {
        EVP_PKEY_CTX_free(context);
        return NULL;
    }

    if (EVP_PKEY_keygen(context, &key) <= 0) {
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(key);
        return NULL;
    }

    EVP_PKEY_CTX_free(context);

    return key;
}

static int validate_rsa_strength(EVP_PKEY *key)
{
    if (key == NULL) {
        return 0;
    }

    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
        return 0;
    }

    if (EVP_PKEY_bits(key) < SIGNER_RSA_BITS) {
        return 0;
    }

    return 1;
}

static int validate_keypair(
    EVP_PKEY *private_key,
    EVP_PKEY *public_key
)
{
    static const unsigned char challenge[] =
        "CHAOS-RELEASE-SIGNER-KEYPAIR-CHECK";

    unsigned char *signature = NULL;
    size_t signature_length = 0;

    EVP_MD_CTX *sign_context = NULL;
    EVP_MD_CTX *verify_context = NULL;

    int result = 0;

    sign_context = EVP_MD_CTX_new();
    verify_context = EVP_MD_CTX_new();

    if (sign_context == NULL || verify_context == NULL) {
        goto cleanup;
    }

    if (EVP_DigestSignInit(
            sign_context,
            NULL,
            EVP_sha256(),
            NULL,
            private_key
        ) <= 0) {
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(
            sign_context,
            challenge,
            sizeof(challenge) - 1
        ) <= 0) {
        goto cleanup;
    }

    if (EVP_DigestSignFinal(
            sign_context,
            NULL,
            &signature_length
        ) <= 0) {
        goto cleanup;
    }

    signature = OPENSSL_malloc(signature_length);
    if (signature == NULL) {
        goto cleanup;
    }

    if (EVP_DigestSignFinal(
            sign_context,
            signature,
            &signature_length
        ) <= 0) {
        goto cleanup;
    }

    if (EVP_DigestVerifyInit(
            verify_context,
            NULL,
            EVP_sha256(),
            NULL,
            public_key
        ) <= 0) {
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(
            verify_context,
            challenge,
            sizeof(challenge) - 1
        ) <= 0) {
        goto cleanup;
    }

    if (EVP_DigestVerifyFinal(
            verify_context,
            signature,
            signature_length
        ) != 1) {
        goto cleanup;
    }

    result = 1;

cleanup:
    OPENSSL_free(signature);
    EVP_MD_CTX_free(sign_context);
    EVP_MD_CTX_free(verify_context);

    return result;
}

static int derive_key_id(
    EVP_PKEY *public_key,
    signer_identity *identity
)
{
    unsigned char *der = NULL;
    unsigned char *cursor;

    unsigned char digest[SHA256_DIGEST_LENGTH];

    int der_length;
    size_t offset;
    size_t i;

    static const char hex[] = "0123456789abcdef";

    der_length = i2d_PUBKEY(public_key, NULL);
    if (der_length <= 0) {
        return 0;
    }

    der = OPENSSL_malloc((size_t)der_length);
    if (der == NULL) {
        return 0;
    }

    cursor = der;

    if (i2d_PUBKEY(public_key, &cursor) != der_length) {
        OPENSSL_free(der);
        return 0;
    }

    if (SHA256(
            der,
            (size_t)der_length,
            digest
        ) == NULL) {
        OPENSSL_free(der);
        return 0;
    }

    OPENSSL_free(der);

    memcpy(
        identity->key_id,
        SIGNER_KEY_ID_PREFIX,
        strlen(SIGNER_KEY_ID_PREFIX)
    );

    offset = strlen(SIGNER_KEY_ID_PREFIX);

    /*
     * SIGNER_KEY_ID_HEX_LENGTH is 16, so use the
     * first 8 bytes of the SHA-256 public-key digest.
     */
    for (i = 0; i < SIGNER_KEY_ID_HEX_LENGTH / 2; ++i) {
        identity->key_id[offset++] =
            hex[(digest[i] >> 4) & 0x0f];

        identity->key_id[offset++] =
            hex[digest[i] & 0x0f];
    }

    identity->key_id[offset] = '\0';

    return 1;
}

int signer_identity_prepare(signer_identity *identity)
{
    int private_exists;
    int public_exists;

    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;

    int result = 0;

    if (identity == NULL) {
        return 0;
    }

    memset(identity, 0, sizeof(*identity));

    private_exists = file_exists(SIGNER_PRIVATE_KEY_FILE);
    public_exists = file_exists(SIGNER_PUBLIC_KEY_FILE);

    /*
     * A public key without its private counterpart represents
     * an existing signing identity that this program cannot
     * recover. Never generate a replacement private key.
     */
    if (!private_exists && public_exists) {
        fprintf(
            stderr,
            "[FAIL] %s is missing.\n",
            SIGNER_PRIVATE_KEY_FILE
        );

        fprintf(
            stderr,
            "[FAIL] Existing signing identity will not be replaced.\n"
        );

        return 0;
    }

    /*
     * First run: neither key exists.
     */
    if (!private_exists && !public_exists) {
        printf("[INFO] No signing identity found.\n");

        printf(
            "[INFO] Generating permanent RSA-%d signing identity...\n",
            SIGNER_RSA_BITS
        );

        private_key = generate_private_key();

        if (private_key == NULL) {
            fprintf(
                stderr,
                "[FAIL] RSA private key generation failed.\n"
            );

            goto cleanup;
        }

        if (!write_private_key(private_key)) {
            fprintf(
                stderr,
                "[FAIL] Could not write %s.\n",
                SIGNER_PRIVATE_KEY_FILE
            );

            goto cleanup;
        }

        printf(
            "[PASS] %s created.\n",
            SIGNER_PRIVATE_KEY_FILE
        );

        if (!write_public_key(private_key)) {
            fprintf(
                stderr,
                "[FAIL] Could not write %s.\n",
                SIGNER_PUBLIC_KEY_FILE
            );

            goto cleanup;
        }

        printf(
            "[PASS] %s created.\n",
            SIGNER_PUBLIC_KEY_FILE
        );
    } else {
        /*
         * Existing private key.
         */
        private_key = load_private_key();

        if (private_key == NULL) {
            fprintf(
                stderr,
                "[FAIL] Could not parse %s.\n",
                SIGNER_PRIVATE_KEY_FILE
            );

            goto cleanup;
        }

        /*
         * The public key is disposable because it can always
         * be deterministically derived from the private key.
         */
        if (!public_exists) {
            printf(
                "[INFO] %s is missing.\n",
                SIGNER_PUBLIC_KEY_FILE
            );

            printf(
                "[INFO] Deriving public key from %s...\n",
                SIGNER_PRIVATE_KEY_FILE
            );

            if (!write_public_key(private_key)) {
                fprintf(
                    stderr,
                    "[FAIL] Could not write %s.\n",
                    SIGNER_PUBLIC_KEY_FILE
                );

                goto cleanup;
            }

            printf(
                "[PASS] %s derived.\n",
                SIGNER_PUBLIC_KEY_FILE
            );
        }
    }

    /*
     * Load both sides from disk. This deliberately verifies
     * the actual persisted identity rather than merely trusting
     * the in-memory key generated above.
     */
    if (private_key != NULL) {
        EVP_PKEY_free(private_key);
        private_key = NULL;
    }

    private_key = load_private_key();
    public_key = load_public_key();

    if (private_key == NULL) {
        fprintf(
            stderr,
            "[FAIL] Could not load %s.\n",
            SIGNER_PRIVATE_KEY_FILE
        );

        goto cleanup;
    }

    if (public_key == NULL) {
        fprintf(
            stderr,
            "[FAIL] Could not load %s.\n",
            SIGNER_PUBLIC_KEY_FILE
        );

        goto cleanup;
    }

    if (!validate_rsa_strength(private_key)) {
        fprintf(
            stderr,
            "[FAIL] Private signing key must be RSA-%d or stronger.\n",
            SIGNER_RSA_BITS
        );

        goto cleanup;
    }

    if (!validate_rsa_strength(public_key)) {
        fprintf(
            stderr,
            "[FAIL] Public signing key must be RSA-%d or stronger.\n",
            SIGNER_RSA_BITS
        );

        goto cleanup;
    }

    printf(
        "[PASS] RSA-%d or stronger validated.\n",
        SIGNER_RSA_BITS
    );

    if (!validate_keypair(
            private_key,
            public_key
        )) {
        fprintf(
            stderr,
            "[FAIL] %s and %s are not a matching keypair.\n",
            SIGNER_PRIVATE_KEY_FILE,
            SIGNER_PUBLIC_KEY_FILE
        );

        goto cleanup;
    }

    printf("[PASS] Signing keypair validated.\n");

    if (!derive_key_id(
            public_key,
            identity
        )) {
        fprintf(
            stderr,
            "[FAIL] Could not derive signing key ID.\n"
        );

        goto cleanup;
    }

    result = 1;

cleanup:
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);

    return result;
}

int signer_identity_print(const signer_identity *identity)
{
    FILE *file;
    char buffer[512];
    size_t count;

    if (identity == NULL) {
        return 0;
    }

    if (identity->key_id[0] == '\0') {
        return 0;
    }

    file = fopen(SIGNER_PUBLIC_KEY_FILE, "rb");

    if (file == NULL) {
        return 0;
    }

    printf("\nKey ID:\n");
    printf("%s\n", identity->key_id);

    printf("\nPublic Key:\n");

    while ((count = fread(
                buffer,
                1,
                sizeof(buffer),
                file
            )) > 0) {
        if (fwrite(
                buffer,
                1,
                count,
                stdout
            ) != count) {
            fclose(file);
            return 0;
        }
    }

    fclose(file);

    printf(
        "\nKeep %s secure. "
        "This signing identity will be reused for future releases.\n\n",
        SIGNER_PRIVATE_KEY_FILE
    );

    return 1;
}