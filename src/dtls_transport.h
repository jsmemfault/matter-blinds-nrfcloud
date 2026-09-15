#ifndef DTLS_TRANSPORT_H_
#define DTLS_TRANSPORT_H_

#include <openthread/ip6.h>
#include <openthread/udp.h>

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <stdint.h>

/* nRF Cloud DTLS session */
struct nrfcloud_session {
	struct {
		void *instance;  /* otInstance* */
		otUdpSocket socket;
		otIp6Address peer_addr;
		uint16_t peer_port;
	} bio;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt ca_cert;
	struct {
		int64_t start;
		uint32_t int_ms;
		uint32_t fin_ms;
	} timer;
};

/*
 * Connect to nRF Cloud: DNS resolve, DTLS handshake, JWT auth.
 * Returns 0 on success. Session is ready for send/recv.
 */
int nrfcloud_connect(struct nrfcloud_session *s);

/* Close DTLS session and UDP socket. */
void nrfcloud_disconnect(struct nrfcloud_session *s);

/*
 * Send data over the DTLS session.
 * Returns bytes sent (>0) or negative mbedTLS error.
 */
int nrfcloud_send(struct nrfcloud_session *s,
		  const uint8_t *buf, size_t len);

/*
 * Receive data from the DTLS session.
 * Returns bytes received (>0) or negative mbedTLS error.
 */
int nrfcloud_recv(struct nrfcloud_session *s,
		  uint8_t *buf, size_t buf_size);

/* Generate a random 1-byte CoAP token. */
uint8_t coap_random_token(void);

/* Serialize access — lock around full connect → send/recv → disconnect sequences. */
extern struct k_mutex nrfcloud_mutex;

#endif /* DTLS_TRANSPORT_H_ */
