<?php

namespace Francerz\OAuth2\AuthServer\Exceptions;

/**
 * Client authentication failed (e.g., unknown client, no client
 * authentication included, or unsupported authentication method). The
 * authorization server MAY return an HTTP 401 (Unauthorized) status code to
 * indicate which authentication schemes are supported. If the client
 * attempted to authenticate via the "Authorization" request header field,
 * the authorization server MUST respond with an HTTP 401 (Unauthorized)
 * status code and include WWW-Authenticate response header field matching
 * with the authentication scheme used by the client.
 */
class TokenInvalidClientException extends OAuth2FlowException
{
}
