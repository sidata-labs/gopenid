# SIData GOpenID

**OpenID Connect Client per CodeIgniter 4**

GOpenID è una libreria PHP per integrare l'autenticazione OpenID Connect (OIDC) nelle applicazioni CodeIgniter 4. Gestisce Authorization Code Flow con PKCE S256, verifica dell'ID Token, identità nella sessione CodeIgniter e RP-Initiated Logout.

La guida seguente mostra come **proteggere globalmente un'applicazione privata** senza dover aggiungere il filtro a ogni singola rotta.

## 1. Requisiti

- PHP 8.3 o superiore (serie 8.x)
- CodeIgniter 4.7 o superiore (serie 4.x)
- Composer
- Un OpenID Provider e un client registrato presso di esso (Client ID e Client Secret)

Il provider deve supportare Authorization Code Flow, PKCE S256, autenticazione `client_secret_basic` e ID Token firmati RS256 con header `kid`. Per il logout federato deve esporre `end_session_endpoint` nel documento OpenID Discovery.

**Compatibilità verificata:** CodeIgniter 4.7.6 e OpenID Provider IASGEST. Altri provider non sono ancora stati collaudati.

## 2. Installazione

Dalla directory principale dell'applicazione CodeIgniter:

```bash
composer require sidata-labs/gopenid
```

Il comando è destinato all'installazione della release pubblicata su Packagist. Non occorre copiare librerie o helper in `app/`, modificare `vendor/` o registrare manualmente servizi.

## 3. Registrazione del client presso il provider

Registrare l'applicazione presso il proprio OpenID Provider e ottenere:

- Client ID e Client Secret
- URL dell'issuer/provider
- URI di callback per il login
- URI di callback per il logout, se utilizzato

Per un'applicazione di esempio `https://miaapplicazione.example`, autorizzare presso il provider:

```text
https://miaapplicazione.example/autenticazione/login_callback
https://miaapplicazione.example/autenticazione/logout_callback
```

Gli URI devono corrispondere **esattamente** a quelli configurati nel client, inclusi schema, host e percorso.

## 4. Configurazione di `.env`

Aggiungere al file `.env` dell'applicazione:

```ini
oauth.client_id = "YOUR_CLIENT_ID"
oauth.client_secret = "YOUR_CLIENT_SECRET"

openid.url = "https://provider.example.com"
openid.redirect = "https://miaapplicazione.example/autenticazione/login_callback"
openid.post_logout_redirect = "https://miaapplicazione.example/autenticazione/logout_callback"

openid.scope = "openid"
openid.login_route = "autenticazione/login"
```

| Parametro | Descrizione |
| --- | --- |
| `oauth.client_id` | Client ID rilasciato dal provider (obbligatorio) |
| `oauth.client_secret` | Client Secret (obbligatorio) |
| `openid.url` | URL del provider (obbligatorio) |
| `openid.redirect` | URI di callback del login (obbligatorio) |
| `openid.post_logout_redirect` | URI di callback del logout (opzionale) |
| `openid.scope` | Scope richiesti; predefinito `openid` |
| `openid.login_route` | Percorso di login usato dal filtro; predefinito `autenticazione/login` |

GOpenID accetta gli scope `openid`, `profile` ed `email`; gli ultimi due richiedono il supporto del provider. Non pubblicare mai la Client Secret in un repository.

## 5. Controller di autenticazione

Creare `app/Controllers/Autenticazione.php`:

```php
<?php

namespace App\Controllers;

class Autenticazione extends BaseController
{
    public function getLogin(): void {
        GOpenID()->login();
    }

    public function getLogin_callback() {
        if (!GOpenID()->authenticate()) return 'Autenticazione non completata.';
        return redirect()->to(site_url('/'));
    }

    public function getLogout_callback() {
        GOpenID()->logout('end');

        return 'Logout eseguito';
    }

    public function getLogout() {
        if (!GOpenID()->logout('pending')) {
            if (!GOpenID()->logout('start')) return redirect()->to(site_url('/'));
        }

        return redirect()->to(GOpenID()->logout('url'));
    }
}
```

**Questo controller è un esempio collaudato, non un file imposto dal pacchetto.** È possibile cambiare il nome del controller, i percorsi e le risposte dopo login/logout.

- `getLogin()` avvia l'autenticazione presso il provider.
- `getLogin_callback()` completa il login e, nell'esempio, torna alla home.
- `getLogout()` riutilizza un logout già in corso (`pending`) oppure ne prepara uno nuovo (`start`), poi usa `url` per il redirect al provider.
- `getLogout_callback()` completa il logout (`end`) e verifica lo `state` quando è configurata la callback.

Se `openid.post_logout_redirect` non è configurato, il provider può terminare il logout senza riportare il browser all'applicazione.

## 6. Configurazione delle rotte

In `app/Config/Routes.php` aggiungere:

```php
$routes->get('autenticazione/login', 'Autenticazione::getLogin');
$routes->get('autenticazione/login_callback', 'Autenticazione::getLogin_callback');
$routes->get('autenticazione/logout', 'Autenticazione::getLogout');
$routes->get('autenticazione/logout_callback', 'Autenticazione::getLogout_callback');
```

Non è necessario abilitare Auto Routing Legacy.

## 7. Proteggere globalmente l'applicazione

**Configurazione consigliata per applicazioni interamente private:** tutte le rotte sono protette, tranne le eccezioni esplicite.

Aprire `app/Config/Filters.php` e aggiungere l'importazione:

```php
use SIData\GOpenID\Filters\OIDCAuthentication;
```

Nell'array `$aliases`, aggiungere:

```php
'oidc' => OIDCAuthentication::class,
```

Nella proprietà `$globals`, aggiungere il filtro alla sezione `before`:

```php
public array $globals = [
    'before' => [
        'oidc' => [
            'except' => [
                'autenticazione/login',
                'autenticazione/login_callback',
                'autenticazione/logout',
                'autenticazione/logout_callback',
            ],
        ],
    ],
    'after' => [
    ],
];
```

**Attenzione:** l'esempio illustra la struttura di `$globals`. Se l'applicazione ha già altri filtri, **non sovrascriverli**: aggiungere soltanto la voce `oidc` preservando le configurazioni esistenti.

Da questo momento, una richiesta non autenticata a `/ordini`, `/clienti`, `/fatture` o `/` viene reindirizzata al login. Le rotte di autenticazione rimangono raggiungibili grazie a `except`.

Se l'applicazione dispone di pagine pubbliche, webhook o API che non devono richiedere un login interattivo, aggiungere le relative eccezioni. Le esclusioni devono corrispondere ai percorsi effettivi.

**Nota:** il controller di esempio torna alla home dopo il login; non implementa il ritorno automatico alla pagina richiesta prima dell'autenticazione.

## 8. Personalizzare il controller e gli URL

Il nome `Autenticazione` non è obbligatorio. Ad esempio, con un controller `Auth` e percorsi `auth/*`, aggiornare il `.env`:

```ini
openid.redirect = "https://miaapplicazione.example/auth/login_callback"
openid.post_logout_redirect = "https://miaapplicazione.example/auth/logout_callback"
openid.login_route = "auth/login"
```

Aggiornare coerentemente le rotte in `Routes.php`, le esclusioni in `Filters.php` e gli URI autorizzati presso il provider. Questa personalizzazione è stata verificata durante i collaudi.

## 9. Utilizzare l'identità dell'utente

L'helper `GOpenID()` è disponibile automaticamente dopo l'installazione Composer.

```php
// Verifica la presenza dell'identità nella sessione applicativa.
$authenticated = GOpenID()->isAuthenticated();

// Claim dell'utente oppure null.
$user = GOpenID()->user();

// Subject Identifier dell'utente oppure null.
$sub = GOpenID()->sub();
```

I claim disponibili dipendono dal provider e dagli scope richiesti. Il claim `sub` identifica l'utente presso il provider: non è necessariamente un ID utente locale.

Il filtro OIDC verifica l'autenticazione, **non** gestisce ruoli o autorizzazioni applicative.

## 10. Logout

GOpenID usa l'`end_session_endpoint` pubblicato dal provider per RP-Initiated Logout. La libreria disattiva l'identità applicativa all'avvio del logout e conserva temporaneamente i dati necessari al protocollo.

Le richieste duplicate possono riutilizzare l'URL di logout preparato entro un TTL di **60 secondi**. Se è configurata la callback, il parametro `state` viene verificato durante `logout('end')`.

Il logout non implica necessariamente la disconnessione da tutte le altre applicazioni collegate allo stesso provider.

## 11. Collaudo rapido

1. Aprire una pagina privata, per esempio `/ordini`, senza autenticazione.
2. Verificare il reindirizzamento al login del provider.
3. Completare il login e verificare il ritorno alla callback.
4. Verificare che `GOpenID()->isAuthenticated()` restituisca `true`.
5. Aprire nuovamente `/ordini`: deve risultare accessibile.
6. Eseguire `/autenticazione/logout` e verificare che l'identità applicativa non risulti più autenticata.

## 12. Problemi comuni

| Problema | Cosa controllare |
| --- | --- |
| `Invalid redirect_uri` | L'URI inviato deve coincidere esattamente con quello autorizzato sul provider. |
| Redirect continuo al login | Verificare `openid.login_route` e le esclusioni in `Filters.php`. |
| Configurazione OpenID mancante | Verificare Client ID, Secret, issuer e callback nel `.env`. |
| Endpoint di logout mancante | Verificare `end_session_endpoint` nel Discovery del provider. |
| `State del logout OIDC non valido` | Verificare sessione, callback e validità della richiesta di logout. |

## 13. Sicurezza

GOpenID utilizza Authorization Code Flow con PKCE S256, valida l'ID Token e richiede firme RS256 con `kid`. Le sessioni devono essere configurate correttamente in CodeIgniter; utilizzare HTTPS in produzione.

La compatibilità con provider diversi da IASGEST richiede ulteriori test.

## 14. Licenza

MIT License — Copyright © 2026 Sidata S.r.l.
