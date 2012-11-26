package org.brekka.phalanx.core.services.impl;

import org.brekka.phalanx.core.model.SecretKeyToken;
import org.brekka.phalanx.core.model.SymedCryptoData;
import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.SecretKey;
import org.brekka.phoenix.api.SymmetricCryptoSpec;

class InternalSecretKeyToken implements SecretKeyToken {

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
    
    public SecretKey getSecretKey() {
        return secretKey;
    }
    
    @Override
    public SymedCryptoData getSymedCryptoData() {
        return symedCryptoData;
    }
}
