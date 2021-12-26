<?php

namespace Francerz\OAuth2\AuthServer\Exceptions;

/**
 * The request is missing a required parameter, includes an invalid
 * parameter value, includes a parameter more than once, or is otherwise
 * malformed.
 */
class AuthorizeInvalidRequestException extends OAuth2FlowException
{
}
