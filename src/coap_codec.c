/*
 * CoAP packet codec — pure C, no Zephyr/OT dependencies.
 */

#include "coap_codec.h"
#include <string.h>
#include <errno.h>

/* Message ID counter (incremented per request) */
static uint16_t coap_msg_id;

void coap_codec_init(void)
{
	coap_msg_id = 0;
}

int coap_append_option(uint8_t *buf, int pos, size_t buf_size,
		       uint16_t *prev_opt, uint16_t opt_num,
		       const void *value, size_t value_len)
{
	uint16_t delta = opt_num - *prev_opt;

	/* Calculate header byte count */
	int hdr_size = 1;

	if (delta >= 269) {
		hdr_size += 2;
	} else if (delta >= 13) {
		hdr_size += 1;
	}
	if (value_len >= 269) {
		hdr_size += 2;
	} else if (value_len >= 13) {
		hdr_size += 1;
	}

	if ((size_t)(pos + hdr_size) + value_len > buf_size) {
		return -ENOMEM;
	}

	/* Encode delta nibble */
	uint8_t d_nibble;

	if (delta < 13) {
		d_nibble = (uint8_t)delta;
	} else if (delta < 269) {
		d_nibble = 13;
	} else {
		d_nibble = 14;
	}

	/* Encode length nibble */
	uint8_t l_nibble;

	if (value_len < 13) {
		l_nibble = (uint8_t)value_len;
	} else if (value_len < 269) {
		l_nibble = 13;
	} else {
		l_nibble = 14;
	}

	buf[pos++] = (d_nibble << 4) | l_nibble;

	/* Extended delta */
	if (delta >= 269) {
		uint16_t ext = delta - 269;

		buf[pos++] = (uint8_t)(ext >> 8);
		buf[pos++] = (uint8_t)(ext & 0xff);
	} else if (delta >= 13) {
		buf[pos++] = (uint8_t)(delta - 13);
	}

	/* Extended length */
	if (value_len >= 269) {
		uint16_t ext = (uint16_t)(value_len - 269);

		buf[pos++] = (uint8_t)(ext >> 8);
		buf[pos++] = (uint8_t)(ext & 0xff);
	} else if (value_len >= 13) {
		buf[pos++] = (uint8_t)(value_len - 13);
	}

	/* Value */
	memcpy(buf + pos, value, value_len);
	pos += (int)value_len;

	*prev_opt = opt_num;
	return pos;
}

int coap_encode_uint(uint8_t *buf, unsigned int val)
{
	if (val == 0) {
		return 0;
	}
	if (val < 0x100) {
		buf[0] = (uint8_t)val;
		return 1;
	}
	if (val < 0x10000) {
		buf[0] = (uint8_t)(val >> 8);
		buf[1] = (uint8_t)(val & 0xff);
		return 2;
	}
	buf[0] = (uint8_t)(val >> 16);
	buf[1] = (uint8_t)((val >> 8) & 0xff);
	buf[2] = (uint8_t)(val & 0xff);
	return 3;
}

int coap_start_request(uint8_t *buf, size_t buf_size, uint8_t code,
		       uint8_t token)
{
	if (buf_size < 5) {
		return -ENOMEM;
	}

	int pos = 0;

	/* Header: Ver=1, Type=CON(0), TKL=1 */
	buf[pos++] = 0x41;
	buf[pos++] = code;
	buf[pos++] = (uint8_t)(coap_msg_id >> 8);
	buf[pos++] = (uint8_t)(coap_msg_id & 0xff);
	coap_msg_id++;
	buf[pos++] = token;

	return pos;
}

int coap_build_post(uint8_t *buf, size_t buf_size,
		    const char *seg1, const char *seg2,
		    const uint8_t *payload, size_t payload_len,
		    uint8_t token)
{
	int pos;
	uint16_t prev_opt = 0;

	pos = coap_start_request(buf, buf_size, COAP_CODE_POST, token);
	if (pos < 0) {
		return pos;
	}

	/* Option: Uri-Path seg1 (option 11) */
	pos = coap_append_option(buf, pos, buf_size, &prev_opt,
				 COAP_OPT_URI_PATH, seg1, strlen(seg1));
	if (pos < 0) {
		return pos;
	}

	/* Option: Uri-Path seg2 (option 11, delta=0) */
	pos = coap_append_option(buf, pos, buf_size, &prev_opt,
				 COAP_OPT_URI_PATH, seg2, strlen(seg2));
	if (pos < 0) {
		return pos;
	}

	/* Option: Content-Format = application/json (50) */
	if (payload_len > 0) {
		uint8_t cf = 50;

		pos = coap_append_option(buf, pos, buf_size, &prev_opt,
					 COAP_OPT_CONTENT_FMT, &cf, 1);
		if (pos < 0) {
			return pos;
		}
	}

	/* Payload */
	if (payload_len > 0) {
		if ((size_t)pos + 1 + payload_len > buf_size) {
			return -ENOMEM;
		}
		buf[pos++] = 0xFF;
		memcpy(buf + pos, payload, payload_len);
		pos += (int)payload_len;
	}

	return pos;
}

int coap_build_proxy_get(uint8_t *buf, size_t buf_size,
			 const char *proxy_uri,
			 uint32_t block_num, uint8_t szx,
			 uint8_t token)
{
	int pos;
	uint16_t prev_opt = 0;
	const char *proxy_path = "proxy";

	pos = coap_start_request(buf, buf_size, COAP_CODE_GET, token);
	if (pos < 0) {
		return pos;
	}

	/* Option: Uri-Path "proxy" (option 11) */
	pos = coap_append_option(buf, pos, buf_size, &prev_opt,
				 COAP_OPT_URI_PATH, proxy_path,
				 strlen(proxy_path));
	if (pos < 0) {
		return pos;
	}

	/* Option: Block2 (option 23) */
	unsigned int block2_val = (block_num << 4) | (szx & 0x07);
	uint8_t block2_buf[3];
	int block2_len = coap_encode_uint(block2_buf, block2_val);

	pos = coap_append_option(buf, pos, buf_size, &prev_opt,
				 COAP_OPT_BLOCK2, block2_buf, block2_len);
	if (pos < 0) {
		return pos;
	}

	/* Option: Proxy-Uri (option 35) */
	pos = coap_append_option(buf, pos, buf_size, &prev_opt,
				 COAP_OPT_PROXY_URI, proxy_uri,
				 strlen(proxy_uri));
	if (pos < 0) {
		return pos;
	}

	/* No payload for GET */
	return pos;
}

int coap_build_proxy_fetch(uint8_t *buf, size_t buf_size,
			   const char *proxy_uri,
			   const char *project_key,
			   uint8_t token)
{
	int pos;
	uint16_t prev_opt = 0;
	const char *proxy_path = "proxy";

	pos = coap_start_request(buf, buf_size, COAP_CODE_FETCH, token);
	if (pos < 0) {
		return pos;
	}

	/* Option: Uri-Path "proxy" (option 11) */
	pos = coap_append_option(buf, pos, buf_size, &prev_opt,
				 COAP_OPT_URI_PATH, proxy_path,
				 strlen(proxy_path));
	if (pos < 0) {
		return pos;
	}

	/* Option: Proxy-Uri (option 35) */
	pos = coap_append_option(buf, pos, buf_size, &prev_opt,
				 COAP_OPT_PROXY_URI, proxy_uri,
				 strlen(proxy_uri));
	if (pos < 0) {
		return pos;
	}

	/* Option: Memfault project key (option 2429) */
	pos = coap_append_option(buf, pos, buf_size, &prev_opt,
				 COAP_OPT_MEMFAULT_KEY, project_key,
				 strlen(project_key));
	if (pos < 0) {
		return pos;
	}

	/* No payload body */
	return pos;
}

int coap_parse_response(const uint8_t *buf, size_t len)
{
	if (len < 4) {
		return -1;
	}
	uint8_t code = buf[1];

	return ((code >> 5) & 0x07) * 100 + (code & 0x1f);
}

/*
 * Decode a CoAP option integer value (big-endian, 0–3 bytes).
 */
static unsigned int decode_uint(const uint8_t *data, size_t len)
{
	unsigned int val = 0;

	for (size_t i = 0; i < len; i++) {
		val = (val << 8) | data[i];
	}
	return val;
}

int coap_parse_response_full(const uint8_t *buf, size_t len,
			     struct coap_response *resp)
{
	if (len < 4) {
		return -EINVAL;
	}

	memset(resp, 0, sizeof(*resp));

	uint8_t code = buf[1];

	resp->code = ((code >> 5) & 0x07) * 100 + (code & 0x1f);

	/* Skip header (4 bytes) + token (TKL from byte 0) */
	uint8_t tkl = buf[0] & 0x0F;
	size_t pos = 4 + tkl;

	if (pos > len) {
		return -EINVAL;
	}

	/* Walk options */
	uint16_t opt_num = 0;

	while (pos < len) {
		uint8_t byte = buf[pos];

		/* Payload marker */
		if (byte == 0xFF) {
			pos++;
			resp->payload = buf + pos;
			resp->payload_len = len - pos;
			return 0;
		}

		/* Decode delta */
		uint8_t d_nibble = (byte >> 4) & 0x0F;
		uint8_t l_nibble = byte & 0x0F;

		pos++;

		uint16_t delta;

		if (d_nibble < 13) {
			delta = d_nibble;
		} else if (d_nibble == 13) {
			if (pos >= len) {
				return -EINVAL;
			}
			delta = buf[pos] + 13;
			pos++;
		} else if (d_nibble == 14) {
			if (pos + 1 >= len) {
				return -EINVAL;
			}
			delta = ((uint16_t)buf[pos] << 8 | buf[pos + 1]) + 269;
			pos += 2;
		} else {
			/* d_nibble == 15 is reserved (payload marker handled above) */
			return -EINVAL;
		}

		uint16_t value_len;

		if (l_nibble < 13) {
			value_len = l_nibble;
		} else if (l_nibble == 13) {
			if (pos >= len) {
				return -EINVAL;
			}
			value_len = buf[pos] + 13;
			pos++;
		} else if (l_nibble == 14) {
			if (pos + 1 >= len) {
				return -EINVAL;
			}
			value_len = ((uint16_t)buf[pos] << 8 | buf[pos + 1]) + 269;
			pos += 2;
		} else {
			return -EINVAL;
		}

		if (pos + value_len > len) {
			return -EINVAL;
		}

		opt_num += delta;

		/* Extract Block2 (option 23) */
		if (opt_num == COAP_OPT_BLOCK2) {
			unsigned int val = decode_uint(buf + pos, value_len);

			resp->has_block2 = true;
			resp->block_num = val >> 4;
			resp->more = (val >> 3) & 1;
			resp->szx = val & 0x07;
		}

		pos += value_len;
	}

	/* No payload marker found — no payload */
	resp->payload = NULL;
	resp->payload_len = 0;
	return 0;
}

int coap_extract_json_url(const char *json, size_t json_len,
			  char *url_out, size_t url_out_size)
{
	const char *needle = "\"url\": \"";
	size_t needle_len = 8; /* strlen("\"url\": \"") */

	/* Find the needle in the JSON */
	const char *p = NULL;

	for (size_t i = 0; i + needle_len <= json_len; i++) {
		if (memcmp(json + i, needle, needle_len) == 0) {
			p = json + i + needle_len;
			break;
		}
	}

	if (!p) {
		/* Try without space: "url":"  */
		needle = "\"url\":\"";
		needle_len = 7;
		for (size_t i = 0; i + needle_len <= json_len; i++) {
			if (memcmp(json + i, needle, needle_len) == 0) {
				p = json + i + needle_len;
				break;
			}
		}
	}

	if (!p) {
		return -ENOENT;
	}

	/* Find closing quote */
	const char *end = json + json_len;
	const char *q = p;

	while (q < end && *q != '"') {
		q++;
	}

	if (q >= end) {
		return -EINVAL;
	}

	size_t url_len = q - p;

	if (url_len + 1 > url_out_size) {
		return -ENOMEM;
	}

	memcpy(url_out, p, url_len);
	url_out[url_len] = '\0';
	return (int)url_len;
}
