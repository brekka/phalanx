package org.brekka.phalanx.core.model;

import java.util.UUID;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;

import org.brekka.phalanx.api.model.CryptedData;

/**
 * A piece of data that is encrypted using a public key and must be decrypted using the corresponding
 * private key (both identified by <code>keyPair</code>).
 * 
 * @author Andrew Taylor
 */
@Entity
@DiscriminatorValue("Asym")
public class AsymedCryptoData extends CryptoData implements CryptedData {

    /**
     * Serial UID
     */
    private static final long serialVersionUID = -5682494152417841750L;
    
    /**
     * The key pair that protects this content
     */
    @OneToOne
    @JoinColumn(name="KeyPairID")
    private AsymmetricKeyPair keyPair;
    
    
    public AsymedCryptoData() {
    }
    
    public AsymedCryptoData(UUID id) {
        setId(id);
    }
    

    public AsymmetricKeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(AsymmetricKeyPair keyPair) {
        this.keyPair = keyPair;
    }
}
