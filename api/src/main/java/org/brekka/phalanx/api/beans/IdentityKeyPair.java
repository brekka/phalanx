package org.brekka.phalanx.api.beans;

import java.util.UUID;

import org.brekka.phalanx.api.model.KeyPair;

public class IdentityKeyPair extends IdentityEntity implements KeyPair {

    /**
     * Serial UID
     */
    private static final long serialVersionUID = -5234267356026490336L;

    public IdentityKeyPair(UUID id) {
        super(id);
    }

}
