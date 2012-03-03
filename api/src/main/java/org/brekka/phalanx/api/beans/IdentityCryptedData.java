package org.brekka.phalanx.api.beans;

import java.util.UUID;

import org.brekka.phalanx.api.model.CryptedData;

public class IdentityCryptedData extends IdentityEntity implements CryptedData {

    /**
     * Serial UID
     */
    private static final long serialVersionUID = -680418169635231980L;

    public IdentityCryptedData(UUID id) {
        super(id);
    }
}
