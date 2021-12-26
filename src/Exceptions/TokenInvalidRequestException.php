<?php

namespace Francerz\OAuth2\AuthServer\Exceptions;

/**
 * The request is missing a required parameter, includes an unsupported
 * parameter value (other than grant type), repeats a parameter, includes
 * multiple credencials, utilizes more than one mechanism for authenticating
 * the client, or is otherwise malformed.
 */
class TokenInvalidRequestException extends OAuth2FlowException
{
}
