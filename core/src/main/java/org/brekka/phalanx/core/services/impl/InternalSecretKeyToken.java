package org.brekka.phalanx.core.services.impl;

import org.brekka.phalanx.core.model.SecretKeyToken;
import org.brekka.phalanx.core.model.SymedCryptoData;
import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.SecretKey;
import org.brekka.phoenix.api.SymmetricCryptoSpec;

class InternalSecretKeyToken implements SecretKeyToken, SymmetricCryptoSpec {

    private final SecretKey secretKey;
    
    private SymedCryptoData symedCryptoData;

    public InternalSecretKeyToken(SecretKey secretKey) {
        this(secretKey, null);
    }
    public InternalSecretKeyToken(SecretKey secretKey, SymedCryptoData symedCryptoData) {
        this.secretKey = secretKey;
        this.symedCryptoData = symedCryptoData;
    }
    
    void setSymedCryptoData(SymedCryptoData symedCryptoData) {
        this.symedCryptoData = symedCryptoData;
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.SymmetricCryptoSpec#getIV()
     */
    @Override
    public byte[] getIV() {
        return symedCryptoData.getIv();
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.CryptoSpec#getProfile()
     */
    @Override
    public CryptoProfile getCryptoProfile() {
        return secretKey.getCryptoProfile();
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.SymmetricCryptoSpec#getKey()
     */
    @Override
    public SecretKey getSecretKey() {
        return secretKey;
    }
    
    @Override
    public SymedCryptoData getSymedCryptoData() {
        return symedCryptoData;
    }
}
