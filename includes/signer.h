#ifndef RELEASE_SIGNER_H
#define RELEASE_SIGNER_H

#include <stddef.h>

#define SIGNER_PRIVATE_KEY_FILE "private.pem"
#define SIGNER_PUBLIC_KEY_FILE  "public.pem"
#define SIGNER_MANIFEST_FILE    "module.json"

#define SIGNER_RSA_BITS 3072
#define SIGNER_KEY_ID_PREFIX "pm-"

#define SIGNER_SHA256_HEX_LENGTH 64
#define SIGNER_KEY_ID_HEX_LENGTH 16

typedef struct signer_identity {
    char key_id[sizeof(SIGNER_KEY_ID_PREFIX) + SIGNER_KEY_ID_HEX_LENGTH];
} signer_identity;

typedef struct release_info {
    char *module;
    char *version;
    char *package_path;
    char *download_url;
    char sha256[SIGNER_SHA256_HEX_LENGTH + 1];
} release_info;

/*
 * Signing identity lifecycle.
 *
 * Both keys missing:
 *     Generate a permanent RSA-3072 private key and matching public key.
 *
 * Private key present, public key missing:
 *     Derive the public key from the existing private key.
 *
 * Public key present, private key missing:
 *     Fail. Never generate a replacement private key automatically.
 *
 * Both keys present:
 *     Validate RSA type, minimum strength, and keypair correspondence.
 */
int signer_identity_prepare(signer_identity *identity);

/* Print the public key and deterministic key ID for developer use. */
int signer_identity_print(const signer_identity *identity);

/* Calculate a package SHA-256 as lowercase hexadecimal. */
int signer_sha256_file(const char *path, char output[SIGNER_SHA256_HEX_LENGTH + 1]);

/*
 * Build the exact ChAoS Core canonical release statement.
 * The returned buffer is heap allocated and contains no trailing newline.
 */
char *signer_release_statement(
    const release_info *release,
    const signer_identity *identity
);

/*
 * Sign the canonical statement with private.pem using RSA/SHA-256,
 * immediately verify it against public.pem, and return a heap-allocated
 * Base64 signature. No signature is returned unless verification passes.
 */
char *signer_release_sign_and_verify(const char *statement);

/* Write the release manifest only after signature verification succeeds. */
int signer_manifest_write(
    const release_info *release,
    const signer_identity *identity,
    const char *signature
);

#endif
