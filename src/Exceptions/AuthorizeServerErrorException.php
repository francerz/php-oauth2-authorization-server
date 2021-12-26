<?php

namespace Francerz\OAuth2\AuthServer\Exceptions;

/**
 * The authorization server encountered an unexepected condition that
 * prevented it from fulfilling the request.
 * (This error is needed because a 500 Internal Server Error HTTP status
 * code cannot be returned to the client via an HTTP redirect.)
 */
class AuthorizeServerErrorException extends OAuth2FlowException
{
}
