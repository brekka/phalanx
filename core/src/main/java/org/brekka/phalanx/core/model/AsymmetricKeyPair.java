package org.brekka.phalanx.core.model;

import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import org.brekka.commons.persistence.model.IdentifiableEntity;
import org.brekka.phalanx.api.model.KeyPair;
import org.hibernate.annotations.Type;

/**
 * Defines the storage of public/private key pair. The private key data will always be unique to a given
 * {@link AsymmetricKeyPair} instance. The public key data may be shared among several {@link AsymmetricKeyPair}
 * instances.
 * 
 * @author Andrew Taylor
 */
@Entity
@Table(name="\"AsymmetricKeyPair\"")
public class AsymmetricKeyPair implements IdentifiableEntity<UUID>, KeyPair {

    /**
     * Serial UID
     */
    private static final long serialVersionUID = 2584665854047069047L;

    @Id
    @Type(type="pg-uuid")
    @Column(name="ID")
    private UUID id;
    
    /**
     * Id of the principal that owns this key pair.
     */
    @ManyToOne
    @JoinColumn(name="OwnerID")
    private Principal owner;
    
    /**
     * The private key data. This should always be an instance of on the {@link CryptoData} sub-types as private keys
     * need to be protected.
     */
    @OneToOne
    @JoinColumn(name="PrivateKeyID", nullable=false)
    private CryptoData privateKey;
    
    /**
     * The public key data, which should just be a plain {@link CryptoData} as it does not need to be encrypted.
     */
    @ManyToOne
    @JoinColumn(name="PublicKeyID", nullable=false)
    private CryptoData publicKey;

    
    

    public AsymmetricKeyPair() {
    }
    
    public AsymmetricKeyPair(UUID id) {
        setId(id);
    }
    
    public final UUID getId() {
        return id;
    }
    
    public final void setId(UUID id) {
        this.id = id;
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
