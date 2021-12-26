<?php

namespace Francerz\OAuth2\AuthServer\Exceptions;

/**
 * The authorization server does not support obtaining an authorization code
 * using this method.
 */
class AuthorizeUnsupportedResponseTypeException extends OAuth2FlowException
{
}
