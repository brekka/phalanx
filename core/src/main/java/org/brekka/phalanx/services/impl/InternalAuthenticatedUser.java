package org.brekka.phalanx.services.impl;

import org.brekka.phalanx.model.AuthenticatedPrincipal;
import org.brekka.phalanx.model.Principal;
import org.brekka.phalanx.model.PrivateKeyToken;

class InternalAuthenticatedUser implements AuthenticatedPrincipal {
    private final Principal user;

    private final InternalPrivateKeyToken privateKey;

    public InternalAuthenticatedUser(Principal user, InternalPrivateKeyToken privateKey) {
        this.user = user;
        this.privateKey = privateKey;
    }

    @Override
    public Principal getPrincipal() {
        return user;
    }

    @Override
    public PrivateKeyToken getDefaultPrivateKey() {
        return privateKey;
    }
}