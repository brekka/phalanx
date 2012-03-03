package org.brekka.phalanx.client.services.impl;

import org.brekka.phalanx.api.model.KeyPair;
import org.brekka.phalanx.api.model.PrivateKeyToken;

class PrivateKeyTokenImpl implements PrivateKeyToken {

    private final byte[] id;
    
    private final KeyPair defaultKeyPair;
    
    private final AuthenticatedPrincipalImpl authenticatedPrincipal;
    
    
    PrivateKeyTokenImpl(byte[] id, KeyPair defaultKeyPair, AuthenticatedPrincipalImpl authenticatedPrincipal) {
        this.id = id;
        this.defaultKeyPair = defaultKeyPair;
        this.authenticatedPrincipal = authenticatedPrincipal;
    }
    
    public byte[] getId() {
        return id;
    }
    
    @Override
    public KeyPair getKeyPair() {
        return defaultKeyPair;
    }

    public AuthenticatedPrincipalImpl getAuthenticatedPrincipal() {
        return authenticatedPrincipal;
    }
}
