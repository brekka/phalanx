package org.brekka.phalanx.client.services.impl;

import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.api.model.Principal;
import org.brekka.phalanx.api.model.PrivateKeyToken;

class AuthenticatedPrincipalImpl implements AuthenticatedPrincipal {

    private final byte[] sessionId;
    
    private final Principal principal;
    
    private final PrivateKeyToken defaultPrivateKey;
    
    AuthenticatedPrincipalImpl(Principal principal, byte[] sessionId, byte[] defaultPrivateKeyId) {
        this.principal = principal;
        this.sessionId = sessionId;
        this.defaultPrivateKey = new PrivateKeyTokenImpl(defaultPrivateKeyId, principal.getDefaultKeyPair(), this);
    }

    @Override
    public Principal getPrincipal() {
        return principal;
    }

    @Override
    public PrivateKeyToken getDefaultPrivateKey() {
        return defaultPrivateKey;
    }
    
    public byte[] getSessionId() {
        return sessionId;
    }
}
