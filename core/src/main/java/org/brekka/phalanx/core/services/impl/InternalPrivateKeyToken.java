package org.brekka.phalanx.core.services.impl;


import org.brekka.phalanx.api.model.PrivateKeyToken;
import org.brekka.phalanx.core.model.AsymmetricKeyPair;
import org.brekka.phalanx.core.model.CryptoData;
import org.brekka.phoenix.api.PrivateKey;

class InternalPrivateKeyToken implements PrivateKeyToken {
    
    private transient final PrivateKey privateKey;
    
    private transient AsymmetricKeyPair asymmetricKeyPair;
    
    /**
     * Needed to assign the private key to others.
     */
    private transient InternalSecretKeyToken secretKey;
    
    public InternalPrivateKeyToken(PrivateKey privateKey, AsymmetricKeyPair asymmetricKeyPair) {
        this.privateKey = privateKey;
        this.asymmetricKeyPair = asymmetricKeyPair;
    }
    
    public InternalPrivateKeyToken(PrivateKey privateKey) {
        this(privateKey, null);
        AsymmetricKeyPair keyPair = new AsymmetricKeyPair();
        CryptoData stubPrivateKey = new CryptoData();
        keyPair.setPrivateKey(stubPrivateKey);
        stubPrivateKey.setProfile(privateKey.getCryptoProfile().getNumber());
        this.asymmetricKeyPair = keyPair;
    }

    @Override
    public AsymmetricKeyPair getKeyPair() {
        return asymmetricKeyPair;
    }
    
    void setAsymetricKeyPair(AsymmetricKeyPair asymetricKeyPair) {
        this.asymmetricKeyPair = asymetricKeyPair;
    }
    
    void setSecretKey(InternalSecretKeyToken secretKey) {
        this.secretKey = secretKey;
    }
    
    PrivateKey getPrivateKey() {
        return privateKey;
    }
    
    InternalSecretKeyToken getSecretKey() {
        return secretKey;
    }
}