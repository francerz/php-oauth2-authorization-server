<?php

namespace Francerz\OAuth2\AuthServer;

interface ClientInterface
{
    public function getClientId(): string;
    public function getClientSecret(): ?string;
    public function getRedirectUri(): ?string;
    public function getClientType(): string;
}
