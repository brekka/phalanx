package org.brekka.phalanx.model;

import java.util.UUID;

import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToOne;
import javax.persistence.Table;

/**
 * A public/private key pair where the private key has been protected by Password based encryption.
 * 
 * @author Andrew Taylor
 */
@Entity
@Table(name="\"AsymmetricKeyPair\"")
public class AsymmetricKeyPair extends IdentifiableEntity {

    @ManyToOne
    @JoinColumn(name="OwnerID")
    private Principal owner;
    
    @OneToOne
    @JoinColumn(name="PrivateKeyID", nullable=false)
    private CryptoData privateKey;
    
    @ManyToOne
    @JoinColumn(name="PublicKeyID", nullable=false)
    private CryptoData publicKey;

    
    

    public AsymmetricKeyPair() {
    }
    
    public AsymmetricKeyPair(UUID id) {
        setId(id);
    }

    public Principal getOwner() {
        return owner;
    }

    public void setOwner(Principal owner) {
        this.owner = owner;
    }

    public CryptoData getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(CryptoData privateKey) {
        this.privateKey = privateKey;
    }

    public CryptoData getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(CryptoData publicKey) {
        this.publicKey = publicKey;
    }
}
