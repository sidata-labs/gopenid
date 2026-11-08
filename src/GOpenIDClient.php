<?php

namespace SIData\GOpenID;

use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;

/**
 * Client OIDC con controlli di sicurezza aggiuntivi.
 */
class GOpenIDClient extends OpenIDConnectClient
{
	protected array $allowedAlgorithms = ['RS256'];

	/**
	 * Restituisce l'endpoint RP-Initiated Logout dichiarato dal provider.
	 */
	public function getEndSessionEndpoint(): string {
		$endpoint = $this->getProviderConfigValue('end_session_endpoint');

		if (!is_string($endpoint) || !filter_var($endpoint, FILTER_VALIDATE_URL)) {
			throw new OpenIDConnectClientException('Endpoint di logout OIDC mancante o non valido nel Discovery.');
		}

		return $endpoint;
	}

	public function verifyJWTSignature(string $jwt): bool {
		$parts = explode('.', $jwt);

		if (count($parts) !== 3) throw new OpenIDConnectClientException('Formato ID Token non valido.');

		$header = json_decode(base64_decode(strtr($parts[0], '-_', '+/'), true));

		if (!is_object($header) || !isset($header->alg) || !is_string($header->alg) || !in_array($header->alg, $this->allowedAlgorithms, true)) {
			throw new OpenIDConnectClientException('Algoritmo di firma OIDC non consentito.');
		}

		// Il provider IASGEST deve specificare il Key ID.
		if (!isset($header->kid) || !is_string($header->kid) || $header->kid === '') {
			throw new OpenIDConnectClientException('Key ID (kid) mancante o non valido nell\'ID Token.');
		}

		return parent::verifyJWTSignature($jwt);
	}

	protected function verifyJWTClaims($claims, string $accessToken = null): bool {
		if (!$this->validateRequiredClaims($claims)) return false;
		return parent::verifyJWTClaims($claims, $accessToken);
	}

	protected function validateRequiredClaims($claims): bool {
		if (!is_object($claims)) return false;

		// Claim obbligatori.
		if (!isset($claims->iss) || !is_string($claims->iss) || $claims->iss === '') return false;
		if (!isset($claims->sub) || !is_string($claims->sub) || $claims->sub === '') return false;
		if (!isset($claims->aud)) return false;
		if (!isset($claims->exp) || !is_int($claims->exp)) return false;
		if (!isset($claims->iat) || !is_int($claims->iat)) return false;

		// Verifica dell'audience.
		if (is_string($claims->aud)) {
			if ($claims->aud !== $this->getClientID()) return false;
		}
		elseif (is_array($claims->aud)) {
			if (empty($claims->aud)) return false;

			foreach ($claims->aud as $aud) {
				if (!is_string($aud) || $aud === '') return false;
			}

			if (!in_array($this->getClientID(), $claims->aud, true)) return false;
		}
		else return false;

		// Verifica del nonce.
		$nonce = $this->getNonce();

		if (!is_string($nonce) || $nonce === '') return false;
		if (!isset($claims->nonce) || !is_string($claims->nonce)) return false;
		if (!hash_equals($nonce, $claims->nonce)) return false;

		// Coerenza temporale.
		$now = time();
		$leeway = $this->getLeeway();

		if ($claims->iat > $now + $leeway) return false;
		if ($claims->exp < $now - $leeway) return false;
		if ($claims->exp <= $claims->iat) return false;

		// Authorized party.
		if (is_array($claims->aud) && count($claims->aud) > 1) {
			if (!isset($claims->azp) || $claims->azp !== $this->getClientID()) return false;
		}

		if (isset($claims->azp) && $claims->azp !== $this->getClientID()) return false;

		return true;
	}
}
