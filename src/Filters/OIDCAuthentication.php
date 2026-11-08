<?php

namespace SIData\GOpenID\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;

class OIDCAuthentication implements FilterInterface
{
    public function before(RequestInterface $request, $arguments = null)
    {
        if (!\GOpenID()->isAuthenticated()) {
            $loginRoute = env('openid.login_route', 'autenticazione/login');

            return redirect()->to(site_url($loginRoute));
        }

        return null;
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        // Nessuna operazione.
    }
}
