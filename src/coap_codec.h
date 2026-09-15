/*
 * CoAP packet codec — pure C, no Zephyr/OT dependencies.
 *
 * Builds and parses CoAP packets per RFC 7252 (options, extended
 * delta/length) and RFC 7959 (Block2 blockwise transfers).
 */

#ifndef COAP_CODEC_H_
#define COAP_CODEC_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* CoAP method codes */
#define COAP_CODE_GET   0x01  /* 0.01 */
#define COAP_CODE_POST  0x02  /* 0.02 */
#define COAP_CODE_FETCH 0x05  /* 0.05 */

/* CoAP option numbers (RFC 7252 + custom) */
#define COAP_OPT_URI_PATH     11
#define COAP_OPT_CONTENT_FMT  12
#define COAP_OPT_BLOCK2       23
#define COAP_OPT_PROXY_URI    35
#define COAP_OPT_MEMFAULT_KEY 2429

/* Block2 size exponent for 1024-byte blocks: 2^(6+4) = 1024 */
#define COAP_BLOCK_SZX_1024 6

/* Reset codec state (message ID counter). Call before deterministic tests. */
void coap_codec_init(void);

/*
 * Append a CoAP option with RFC 7252 extended delta/length encoding.
 *
 * @param buf      Packet buffer
 * @param pos      Current write position in buffer
 * @param buf_size Total buffer capacity
 * @param prev_opt Running option number (updated on success)
 * @param opt_num  Option number to append
 * @param value    Option value bytes
 * @param value_len Option value length
 * @return New buffer position, or negative errno on error
 */
int coap_append_option(uint8_t *buf, int pos, size_t buf_size,
		       uint16_t *prev_opt, uint16_t opt_num,
		       const void *value, size_t value_len);

/*
 * Encode an unsigned integer as big-endian bytes (RFC 7252 option value format).
 *
 * @param buf  Output buffer (at least 3 bytes)
 * @param val  Value to encode
 * @return Number of bytes written (0–3)
 */
int coap_encode_uint(uint8_t *buf, unsigned int val);

/*
 * Build a CoAP CON request header (5 bytes: ver/type/tkl, code, msg_id, token).
 *
 * @param buf      Packet buffer
 * @param buf_size Buffer capacity
 * @param code     Method code (COAP_CODE_GET, COAP_CODE_POST, etc.)
 * @param token    Token byte to embed in the header
 * @return Position after header (5), or negative errno on error
 */
int coap_start_request(uint8_t *buf, size_t buf_size, uint8_t code,
		       uint8_t token);

/*
 * Build a CoAP CON POST to a two-segment path with optional JSON payload.
 *
 * @param buf         Packet buffer
 * @param buf_size    Buffer capacity
 * @param seg1        First path segment (e.g., "auth")
 * @param seg2        Second path segment (e.g., "jwt")
 * @param payload     Payload bytes (NULL if none)
 * @param payload_len Payload length (0 if none)
 * @param token       Token byte
 * @return Total packet length, or negative errno on error
 */
int coap_build_post(uint8_t *buf, size_t buf_size,
		    const char *seg1, const char *seg2,
		    const uint8_t *payload, size_t payload_len,
		    uint8_t token);

/*
 * Build a CoAP CON GET to /proxy with Proxy-Uri and Block2 option.
 * Options in ascending order: Uri-Path(11) → Block2(23) → Proxy-Uri(35).
 * No payload marker.
 *
 * @param buf        Packet buffer
 * @param buf_size   Buffer capacity
 * @param proxy_uri  Full HTTPS URL for the proxy to fetch
 * @param block_num  Block number to request (0-based)
 * @param szx        Block size exponent (e.g., COAP_BLOCK_SZX_1024)
 * @param token      Token byte
 * @return Total packet length, or negative errno on error
 */
int coap_build_proxy_get(uint8_t *buf, size_t buf_size,
			 const char *proxy_uri,
			 uint32_t block_num, uint8_t szx,
			 uint8_t token);

/*
 * Build a CoAP CON FETCH to /proxy with Proxy-Uri and project key option.
 * Options: Uri-Path(11) → Proxy-Uri(35) → Memfault key(2429).
 * No payload body.
 *
 * @param buf         Packet buffer
 * @param buf_size    Buffer capacity
 * @param proxy_uri   Full HTTPS URL for the proxy to fetch
 * @param project_key Memfault project key string
 * @param token       Token byte
 * @return Total packet length, or negative errno on error
 */
int coap_build_proxy_fetch(uint8_t *buf, size_t buf_size,
			   const char *proxy_uri,
			   const char *project_key,
			   uint8_t token);

/*
 * Parse CoAP response code from raw packet.
 *
 * @param buf Response buffer
 * @param len Response length
 * @return Response code as class*100 + detail (e.g., 201 for 2.01),
 *         or -1 on error
 */
int coap_parse_response(const uint8_t *buf, size_t len);

/* Parsed CoAP response with payload and Block2 option */
struct coap_response {
	int code;                /* e.g., 205 for 2.05 Content */
	const uint8_t *payload;  /* pointer into original buffer */
	size_t payload_len;
	bool has_block2;
	uint32_t block_num;
	bool more;
	uint8_t szx;
};

/*
 * Parse a CoAP response fully: code, options (Block2), and payload.
 *
 * @param buf  Response buffer
 * @param len  Response length
 * @param resp Output struct (payload pointer points into buf)
 * @return 0 on success, negative errno on error
 */
int coap_parse_response_full(const uint8_t *buf, size_t len,
			     struct coap_response *resp);

/*
 * Extract a URL from nRF Cloud proxy JSON response.
 * Expected format: {"data": {"url": "https://..."}}
 *
 * @param json       JSON string (not necessarily null-terminated)
 * @param json_len   Length of JSON data
 * @param url_out    Output buffer for extracted URL (null-terminated)
 * @param url_out_size Size of url_out buffer
 * @return Length of URL on success, negative errno on error
 */
int coap_extract_json_url(const char *json, size_t json_len,
			  char *url_out, size_t url_out_size);

#endif /* COAP_CODEC_H_ */
