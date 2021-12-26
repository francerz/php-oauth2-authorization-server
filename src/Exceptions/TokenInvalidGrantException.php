<?php

namespace Francerz\OAuth2\AuthServer\Exceptions;

/**
 * The provided authorization grant (e.g., authorization code, resource
 * owner credentials) or refresh token is invalid, expired, revoked, does
 * not match the redirection URI used in the authorization request, or was
 * issued to another client.
 */
class TokenInvalidGrantException extends OAuth2FlowException
{
}
