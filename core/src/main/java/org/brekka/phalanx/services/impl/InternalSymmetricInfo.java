package org.brekka.phalanx.services.impl;

import java.io.Serializable;

import org.brekka.phalanx.model.SymmetricInfo;
import org.brekka.xml.v1.phalanx.SymmetricInfoType;

final class InternalSymmetricInfo implements Serializable, SymmetricInfo {
    /**
     * Serial UID
     */
    private static final long serialVersionUID = 6451869664440169850L;

    private final SymmetricInfoType symmetricInfoType; 

    public InternalSymmetricInfo(SymmetricInfoType symmetricInfoType) {
        this.symmetricInfoType = symmetricInfoType;
    }

    /* (non-Javadoc)
     * @see org.brekka.polaris.crypto.SymmetricParameters#getProfileId()
     */
    @Override
    public int getProfileId() {
        return symmetricInfoType.getProfile();
    }

    /* (non-Javadoc)
     * @see org.brekka.polaris.crypto.SymmetricParameters#getKey()
     */
    @Override
    public byte[] getKey() {
        return symmetricInfoType.getKey();
    }

    /* (non-Javadoc)
     * @see org.brekka.polaris.crypto.SymmetricParameters#getIv()
     */
    @Override
    public byte[] getIv() {
        return symmetricInfoType.getIV();
    }
    
    SymmetricInfoType getSymmetricInfoType() {
        return symmetricInfoType;
    }
}
