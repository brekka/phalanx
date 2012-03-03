package org.brekka.phalanx.api.beans;

import java.io.Serializable;
import java.util.UUID;

abstract class IdentityEntity implements Serializable {

    /**
     * Serial UID
     */
    private static final long serialVersionUID = 1722300393338114364L;
    
    private final UUID id;

    protected IdentityEntity(UUID id) {
        this.id = id;
    }
    
    public final UUID getId() {
        return id;
    }
}
