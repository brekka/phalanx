package org.brekka.phalanx.services.impl;

import javax.crypto.SecretKey;

import org.brekka.phalanx.model.SecretKeyToken;
import org.brekka.phalanx.model.SymedCryptoData;

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
    
    public SecretKey getSecretKey() {
        return secretKey;
    }
    
    void setSymedCryptoData(SymedCryptoData symedCryptoData) {
        this.symedCryptoData = symedCryptoData;
    }
    
    @Override
    public SymedCryptoData getSymedCryptoData() {
        return symedCryptoData;
    }
}
