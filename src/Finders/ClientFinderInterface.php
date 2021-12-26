<?php

namespace Francerz\OAuth2\AuthServer\Finders;

use Francerz\OAuth2\AuthServer\ClientInterface;

interface ClientFinderInterface
{
    public function findClient(string $clientId): ?ClientInterface;
}
