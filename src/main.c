#include "../includes/signer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIGNER_INPUT_SIZE 2048

static int read_input(
    const char *prompt,
    char *buffer,
    size_t buffer_size
)
{
    size_t length;
    int character;

    if (prompt == NULL
        || buffer == NULL
        || buffer_size < 2) {
        return 0;
    }

    printf("%s", prompt);
    fflush(stdout);

    if (fgets(buffer, (int)buffer_size, stdin) == NULL) {
        return 0;
    }

    length = strlen(buffer);

    if (length > 0 && buffer[length - 1] == '\n') {
        buffer[--length] = '\0';

        if (length > 0 && buffer[length - 1] == '\r') {
            buffer[--length] = '\0';
        }
    } else {
        character = getchar();

        if (character != '\n' && character != EOF) {
            while ((character = getchar()) != '\n' && character != EOF) {
                /* Discard overlong input. */
            }

            fprintf(
                stderr,
                "[FAIL] Input exceeds maximum supported length.\n"
            );

            buffer[0] = '\0';
            return 0;
        }
    }

    if (length == 0) {
        fprintf(stderr, "[FAIL] A value is required.\n");
        return 0;
    }

    return 1;
}

static int contains_line_break(const char *value)
{
    if (value == NULL) {
        return 1;
    }

    return strchr(value, '\r') != NULL
        || strchr(value, '\n') != NULL;
}

static int validate_release_field(
    const char *label,
    const char *value
)
{
    if (value == NULL || value[0] == '\0') {
        fprintf(stderr, "[FAIL] %s is required.\n", label);
        return 0;
    }

    if (contains_line_break(value)) {
        fprintf(
            stderr,
            "[FAIL] %s may not contain line breaks.\n",
            label
        );

        return 0;
    }

    return 1;
}

static int validate_download_url(const char *url)
{
    static const char prefix[] = "https://";

    if (!validate_release_field("Download URL", url)) {
        return 0;
    }

    if (strncmp(url, prefix, sizeof(prefix) - 1) != 0) {
        fprintf(
            stderr,
            "[FAIL] Download URL must use HTTPS.\n"
        );

        return 0;
    }

    return 1;
}

int main(void)
{
    signer_identity identity;
    release_info release;

    char module[SIGNER_INPUT_SIZE];
    char version[SIGNER_INPUT_SIZE];
    char package_path[SIGNER_INPUT_SIZE];
    char download_url[SIGNER_INPUT_SIZE];

    char *statement = NULL;
    char *signature = NULL;

    int exit_code = EXIT_FAILURE;

    memset(&identity, 0, sizeof(identity));
    memset(&release, 0, sizeof(release));

    printf("ChAoS Release Signer\n");
    printf("====================\n\n");

    if (!signer_identity_prepare(&identity)) {
        fprintf(
            stderr,
            "\n[FAIL] Signing identity preparation failed.\n"
        );

        goto cleanup;
    }

    if (!signer_identity_print(&identity)) {
        fprintf(
            stderr,
            "[FAIL] Could not display signing identity.\n"
        );

        goto cleanup;
    }

    if (!read_input(
            "Module: ",
            module,
            sizeof(module)
        )) {
        goto cleanup;
    }

    if (!validate_release_field("Module", module)) {
        goto cleanup;
    }

    if (!read_input(
            "Version: ",
            version,
            sizeof(version)
        )) {
        goto cleanup;
    }

    if (!validate_release_field("Version", version)) {
        goto cleanup;
    }

    if (!read_input(
            "Package: ",
            package_path,
            sizeof(package_path)
        )) {
        goto cleanup;
    }

    if (!validate_release_field("Package", package_path)) {
        goto cleanup;
    }

    if (!read_input(
            "Download URL: ",
            download_url,
            sizeof(download_url)
        )) {
        goto cleanup;
    }

    if (!validate_download_url(download_url)) {
        goto cleanup;
    }

    release.module = module;
    release.version = version;
    release.package_path = package_path;
    release.download_url = download_url;

    printf("\nCalculating package SHA-256...\n");

    if (!signer_sha256_file(
            release.package_path,
            release.sha256
        )) {
        goto cleanup;
    }

    printf(
        "[PASS] Package SHA-256 calculated.\n"
        "SHA-256: %s\n",
        release.sha256
    );

    statement = signer_release_statement(
        &release,
        &identity
    );

    if (statement == NULL) {
        fprintf(
            stderr,
            "[FAIL] Could not construct canonical release statement.\n"
        );

        goto cleanup;
    }

    printf(
        "\n[PASS] Canonical release statement generated.\n"
        "\nCanonical Statement:\n"
        "%s\n",
        statement
    );

    signature = signer_release_sign_and_verify(statement);

    if (signature == NULL) {
        fprintf(
            stderr,
            "\n[FAIL] No release manifest was written.\n"
        );

        goto cleanup;
    }

    printf(
        "\nVerified Signature:\n"
        "%s\n",
        signature
    );

    if (!signer_manifest_write(
            &release,
            &identity,
            signature
        )) {
        fprintf(
            stderr,
            "\n[FAIL] Release manifest creation failed.\n"
        );

        goto cleanup;
    }

    printf(
        "\nRelease ready.\n"
        "Module: %s\n"
        "Version: %s\n"
        "Package: %s\n"
        "SHA-256: %s\n"
        "Key ID: %s\n"
        "Manifest: %s\n",
        release.module,
        release.version,
        release.package_path,
        release.sha256,
        identity.key_id,
        SIGNER_MANIFEST_FILE
    );

    exit_code = EXIT_SUCCESS;

cleanup:
    free(statement);
    free(signature);

    if (exit_code != EXIT_SUCCESS) {
        fprintf(
            stderr,
            "\nRelease signing did not complete.\n"
        );
    }

    return exit_code;
}
