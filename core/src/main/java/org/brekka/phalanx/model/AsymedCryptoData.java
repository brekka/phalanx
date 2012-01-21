package org.brekka.phalanx.model;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;

@Entity
@DiscriminatorValue("Asym")
public class AsymedCryptoData extends CryptoData {

    /**
     * The key pair that protects this content
     */
    @OneToOne
    @JoinColumn(name="KeyPairID")
    private AsymmetricKeyPair keyPair;

    public AsymmetricKeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(AsymmetricKeyPair keyPair) {
        this.keyPair = keyPair;
    }
}
