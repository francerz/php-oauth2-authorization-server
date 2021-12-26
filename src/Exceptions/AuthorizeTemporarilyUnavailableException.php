<?php

namespace Francerz\OAuth2\AuthServer\Exceptions;

/**
 * The authorization server is currently unable to handle the request due
 * to a temporary overloading or maintenance of the server. (This error is
 * needed because a 503 Service Unavailable HTTP status code cannot be
 * returned to the client via an HTTP redirect.)
 */
class AuthorizeTemporarilyUnavailableException extends OAuth2FlowException
{
}
