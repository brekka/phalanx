package org.brekka.phalanx.api.beans;

import java.util.UUID;

import org.brekka.phalanx.api.model.KeyPair;
import org.brekka.phalanx.api.model.Principal;

public class IdentityPrincipal extends IdentityEntity implements Principal {

    /**
     * Serial UID
     */
    private static final long serialVersionUID = 19657271910763244L;

    public IdentityPrincipal(UUID id) {
        super(id);
    }

    @Override
    public KeyPair getDefaultKeyPair() {
        return null;
    }

}
