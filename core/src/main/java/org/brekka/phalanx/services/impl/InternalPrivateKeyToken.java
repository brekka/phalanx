package org.brekka.phalanx.services.impl;

import java.security.PrivateKey;

import org.brekka.phalanx.model.AsymmetricKeyPair;
import org.brekka.phalanx.model.CryptoData;
import org.brekka.phalanx.model.PrivateKeyToken;

class InternalPrivateKeyToken implements PrivateKeyToken {
    private transient final PrivateKey privateKey;
    
    private transient AsymmetricKeyPair asymmetricKeyPair;
    
    public InternalPrivateKeyToken(PrivateKey privateKey) {
        this(privateKey, null);
    }
    
    public InternalPrivateKeyToken(PrivateKey privateKey, AsymmetricKeyPair asymmetricKeyPair) {
        this.privateKey = privateKey;
        this.asymmetricKeyPair = asymmetricKeyPair;
    }
    
    public InternalPrivateKeyToken(PrivateKey privateKey, int profileId) {
        this(privateKey, null);
        AsymmetricKeyPair keyPair = new AsymmetricKeyPair();
        CryptoData stubPrivateKey = new CryptoData();
        keyPair.setPrivateKey(stubPrivateKey);
        stubPrivateKey.setProfile(profileId);
        this.asymmetricKeyPair = keyPair;
    }

    @Override
    public AsymmetricKeyPair getKeyPair() {
        return asymmetricKeyPair;
    }
    
    void setAsymetricKeyPair(AsymmetricKeyPair asymetricKeyPair) {
        this.asymmetricKeyPair = asymetricKeyPair;
    }
    
    PrivateKey getPrivateKey() {
        return privateKey;
    }
}