<?php

namespace Francerz\OAuth2\AuthServer\Exceptions;

/**
 * The requested scope is invalid, unknown, malformed, or exceeds the scope
 * granted by the resource owner.
 */
class TokenInvalidScopeException extends OAuth2FlowException
{
}
