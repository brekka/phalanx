package org.brekka.phalanx.client.services.impl;

import java.util.UUID;

import org.brekka.phalanx.api.model.KeyPair;
import org.brekka.phalanx.api.model.Principal;

class PrincipalImpl implements Principal {

    private final UUID id;
    
    private final KeyPair defaultKeyPair;
    
    PrincipalImpl(UUID id, KeyPair defaultKeyPair) {
        this.id = id;
        this.defaultKeyPair = defaultKeyPair;
    }

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public KeyPair getDefaultKeyPair() {
        return defaultKeyPair;
    }

}
