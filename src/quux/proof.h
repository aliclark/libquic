/*
 * Proof.h
 *
 *  Created on: Jul 2, 2016
 *      Author: user
 */

#ifndef SRC_QUUX_PROOF_H_
#define SRC_QUUX_PROOF_H_

#include <base/memory/ref_counted.h>
#include <base/strings/string_piece.h>
#include <net/base/ip_address.h>
#include <net/quic/crypto/proof_source.h>
#include <net/quic/crypto/proof_verifier.h>
#include <net/quic/crypto/quic_crypto_client_config.h>
#include <net/quic/quic_crypto_client_stream.h>
#include <net/quic/quic_protocol.h>
#include <net/quic/quic_types.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace quux {

namespace proof {

class Source: public net::ProofSource {
public:
	Source(): ProofSource() {
		certs.push_back("cert1");
		chain = new net::ProofSource::Chain(certs);
	}

	bool GetProof(const net::IPAddress& /*server_ip*/, const std::string& /*hostname*/,
			const std::string& /*server_config*/, net::QuicVersion /*quic_version*/,
			base::StringPiece /*chlo_hash*/, bool /*ecdsa_ok*/,
			scoped_refptr<Chain>* out_chain, std::string* out_signature,
			std::string* out_leaf_cert_sct) override {

		*out_chain = chain;
		*out_signature = "clients_sig";
		*out_leaf_cert_sct = signed_certificate_timestamp;
		return true;
	}

	std::vector<std::string> certs;
	scoped_refptr<ProofSource::Chain> chain;
	const std::string signed_certificate_timestamp = "sc_timestamp";
};

class Verifier: public net::ProofVerifier {
public:
	net::QuicAsyncStatus VerifyProof(const std::string& hostname,
			const uint16_t /*port*/, const std::string& /*server_config*/,
			net::QuicVersion /*quic_version*/, base::StringPiece /*chlo_hash*/,
			const std::vector<std::string>& /*certs*/, const std::string& /*cert_sct*/,
			const std::string& /*signature*/,
			const net::ProofVerifyContext* /*context*/, std::string* /*error_details*/,
			std::unique_ptr<net::ProofVerifyDetails>* /*details*/,
			net::ProofVerifierCallback* /*callback*/) override {

		// sure whatever
		return net::QuicAsyncStatus::QUIC_SUCCESS;
	}
};

class Handler: public net::QuicCryptoClientStream::ProofHandler {
public:
	void OnProofValid(const net::QuicCryptoClientConfig::CachedState& /*cached*/)
			override {
	}
	void OnProofVerifyDetailsAvailable(
			const net::ProofVerifyDetails& verify_details) override {
	}
};

} /* namespace proof */

} /* namespace quux */

#endif /* SRC_QUUX_PROOF_H_ */
