package org.brekka.phalanx.core.services.impl;

import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.api.model.Principal;
import org.brekka.phalanx.api.model.PrivateKeyToken;

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