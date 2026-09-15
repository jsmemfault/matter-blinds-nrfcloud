#ifndef JWT_H_
#define JWT_H_

#include <stddef.h>
#include <stdint.h>

#include <psa/crypto.h>

/**
 * Generate an ES256-signed JWT using an existing PSA key handle.
 *
 * This is the path used once the device is provisioned: the signing key is a
 * persistent, non-exportable key created on-die, so there is no raw scalar to
 * pass around. See provisioning.h.
 *
 * @param device_id  Device ID string (becomes "sub" claim)
 * @param unix_time  Current unix timestamp (becomes "iat", exp = iat + 3600)
 * @param key_id     PSA key handle with PSA_KEY_USAGE_SIGN_MESSAGE
 * @param jwt_buf    Output buffer for the JWT string (null-terminated)
 * @param jwt_buf_size Size of jwt_buf (recommend >= 400)
 * @return 0 on success, negative errno on failure
 */
int jwt_generate_psa(const char *device_id, uint32_t unix_time,
		     psa_key_id_t key_id,
		     char *jwt_buf, size_t jwt_buf_size);

/**
 * Generate an ES256-signed JWT from a raw private key scalar.
 *
 * Imports @private_key into a volatile PSA slot and delegates to
 * jwt_generate_psa(). Retained for unprovisioned devices.
 *
 * @param private_key Raw 32-byte EC P-256 private key scalar (big-endian)
 * @param key_len    Length of private_key (must be 32)
 */
int jwt_generate(const char *device_id, uint32_t unix_time,
		 const uint8_t *private_key, size_t key_len,
		 char *jwt_buf, size_t jwt_buf_size);

/**
 * Resolve the key to sign nRF Cloud JWTs with.
 *
 * Returns the provisioned on-die key when CONFIG_PROVISIONING is enabled and
 * the device has been through the factory flow, otherwise a volatile key
 * imported from credentials.h. Callers do not need to know which.
 *
 * @return 0 on success, -ENOENT if the device has no usable identity
 */
int jwt_signing_key(psa_key_id_t *key_id);

/* Get current unix time (0 if not set). */
uint32_t get_current_time(void);

/* Sync time via SNTP over NAT64. Returns 0 on success. */
int sntp_sync(const char *hostname);

/* Shell commands (registered in nrfcloud_shell.c) */
#ifdef CONFIG_SHELL
struct shell;
int cmd_nrfcloud_jwt(const struct shell *sh, size_t argc, char **argv);
int cmd_nrfcloud_time(const struct shell *sh, size_t argc, char **argv);
int cmd_nrfcloud_sntp(const struct shell *sh, size_t argc, char **argv);
#endif /* CONFIG_SHELL */

#endif /* JWT_H_ */
