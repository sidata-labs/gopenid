<?php

namespace SIData\GOpenID;

use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\Session\Session;

/**
* Gestione applicativa OpenID Connect.
*/
class GOpenID
{
	protected const SESSION_KEY = 'openid_user';
	protected const ID_TOKEN_SESSION_KEY = 'openid_id_token';
	protected const LOGOUT_STATE_SESSION_KEY = 'openid_logout_state';
	protected const LOGOUT_URL = 'openid_logout_url';
	protected const LOGOUT_CREATED_AT = 'openid_logout_created_at';
	protected const LOGOUT_TTL = 60;
	protected array $config = [];
	protected ?GOpenIDClient $client = null;

	private RequestInterface $request;
	private const PKCE_METHOD = 'S256';

	public function __construct() {
		$this->config = [
			'client_id'             => getEnv('oauth.client_id'),
			'client_secret'         => getEnv('oauth.client_secret'),
			'url'                   => rtrim(getEnv('openid.url'), '/'),
			'redirect'              => getEnv('openid.redirect'),
			'post_logout_redirect'  => getEnv('openid.post_logout_redirect'),
			'scope'                 => getEnv('openid.scope') ?: 'openid',
		];

		$this->request = service('request');
		$this->validateConfig();
	}

	protected function session(): Session {
		$session = service('session');
		if (session_status() === PHP_SESSION_NONE) $session->start();
		return $session;
	}

	protected function validateConfig(): void {
		foreach (['client_id', 'client_secret', 'url', 'redirect'] as $key) {
			if (empty($this->config[$key])) throw new \RuntimeException("Configurazione OpenID mancante: {$key}");
		}

		$scopes = preg_split('/\s+/', trim($this->config['scope']), -1, PREG_SPLIT_NO_EMPTY) ?: [];
		$allowedScopes = ['openid', 'profile', 'email'];

		if (!filter_var($this->config['url'], FILTER_VALIDATE_URL)) throw new \RuntimeException('URL OpenID non valido.');
		if (!filter_var($this->config['redirect'], FILTER_VALIDATE_URL)) throw new \RuntimeException('Redirect OpenID non valido.');
		if (!empty($this->config['post_logout_redirect']) && !filter_var($this->config['post_logout_redirect'], FILTER_VALIDATE_URL)) throw new \RuntimeException('Post logout redirect OpenID non valido.');
		if (!in_array('openid', $scopes, true) || array_diff($scopes, $allowedScopes)) throw new \RuntimeException('Configurazione scope OpenID non valida.');
	}

	public function config(): array {
		$config = $this->config;
		unset($config['client_secret']);

		return $config;
	}

	public function client(): GOpenIDClient {
		if ($this->client === null) {
			$session = $this->session();

			$this->client = new GOpenIDClient($this->config['url'], $this->config['client_id'], $this->config['client_secret']);

			$this->client->setRedirectURL($this->config['redirect']);
			$this->client->setCodeChallengeMethod(self::PKCE_METHOD);
			$this->client->addScope(preg_split('/\s+/', trim($this->config['scope'])));
			$this->client->setTokenEndpointAuthMethodsSupported(['client_secret_basic']);
		}

		return $this->client;
	}

	/**
	 * Completa l'autenticazione OIDC e memorizza l'identità.
	 */
	public function authenticate(): bool {
		$client = $this->client();

		if (!$client->authenticate()) return false;

		$idToken = $client->getIdToken();

		if (!is_string($idToken) || $idToken === '') throw new \RuntimeException('ID Token OIDC mancante.');

		$claims = $client->getVerifiedClaims();
		$user = (array)$claims;

		if (empty($user['sub'])) throw new \RuntimeException('Identificativo utente OIDC mancante.');

		$session = $this->session();

		$session->remove([
			self::LOGOUT_URL,
			self::LOGOUT_CREATED_AT,
			self::LOGOUT_STATE_SESSION_KEY
		]);

		$session->set([
			self::ID_TOKEN_SESSION_KEY => $idToken,
			self::SESSION_KEY => $user
		]);

		return true;
	}

	/**
	* Verifica se esiste un'identità autenticata.
	*/
	public function isAuthenticated(): bool {
		$user = $this->user();
		return !empty($user['sub']);
	}

	/**
	* Restituisce i claim dell'utente autenticato.
	*/
	public function user(): ?array {
		$user = $this->session()->get(self::SESSION_KEY);
		return is_array($user) ? $user : null;
	}

	/**
	* Restituisce il Subject Identifier dell'utente.
	*/
	public function sub(): ?string {
		return $this->user()['sub'] ?? null;
	}

	public function login(): void {
		$this->client()->authenticate();
	}

	/**
	* Prepara la richiesta di logout OIDC e restituisce l'URL del provider.
	*/
	private function logoutStart() {
		$session = $this->session();

		if ($this->logoutPending()) return true;

		$idToken = $session->get(self::ID_TOKEN_SESSION_KEY);

		if (!is_string($idToken) || $idToken === '') return false;

		$logoutEndpoint = rtrim($this->client()->getEndSessionEndpoint(), '?&');
		$separator = str_contains($logoutEndpoint, '?') ? '&' : '?';

		$session->remove(self::SESSION_KEY);

		$params = ['id_token_hint' => $idToken];

		if (!empty($this->config['post_logout_redirect'])) {
			$state = bin2hex(random_bytes(32));

			$session->set(self::LOGOUT_STATE_SESSION_KEY, $state);

			$params['post_logout_redirect_uri'] = $this->config['post_logout_redirect'];
			$params['state'] = $state;
		}
		else {
			$this->logoutEnd();
		}

		$session->set([
			self::LOGOUT_URL => $logoutEndpoint.$separator.http_build_query($params, '', '&', PHP_QUERY_RFC3986),
			self::LOGOUT_CREATED_AT => time()
		]);

		return true;
	}

	private function logoutPending(): bool {
		$session = $this->session();

		$url = $session->get(self::LOGOUT_URL);
		$createdAt = $session->get(self::LOGOUT_CREATED_AT);

		if (!is_string($url) || $url === '') return false;

		if (!is_numeric($createdAt) || time() - (int)$createdAt >= self::LOGOUT_TTL) {
			$session->remove([
				self::LOGOUT_URL,
				self::LOGOUT_CREATED_AT,
				self::LOGOUT_STATE_SESSION_KEY,
				self::ID_TOKEN_SESSION_KEY
			]);

			return false;
		}

		return true;
	}

	private function logoutEnd(): void {
		$session = $this->session();

		$keys = [
			self::SESSION_KEY,
			self::ID_TOKEN_SESSION_KEY,
			self::LOGOUT_STATE_SESSION_KEY
		];

		if (!empty($this->config['post_logout_redirect'])) {

			// Verifica che il logout sia ancora valido.
			if (!$this->logoutPending()) throw new \RuntimeException('Logout OIDC scaduto o non presente.');

			// Verifica lo state della callback.
			$expectedState = $session->get(self::LOGOUT_STATE_SESSION_KEY);
			$receivedState = $this->request->getGet('state');

			if (!is_string($expectedState) || $expectedState === '' || !is_string($receivedState) || !hash_equals($expectedState, $receivedState)) throw new \RuntimeException('State del logout OIDC non valido.');

			$keys[] = self::LOGOUT_URL;
			$keys[] = self::LOGOUT_CREATED_AT;
		}

		$session->remove($keys);
	}

	public function logout(string $action): mixed {
		$session = $this->session();

		return match ($action) {
			'url' => $session->get(self::LOGOUT_URL),
			'start' => $this->logoutStart(),
			'pending' => $this->logoutPending(),
			'end' => $this->logoutEnd(),
			default => throw new \InvalidArgumentException("Azione logout non valida: {$action}")
		};
	}
}
