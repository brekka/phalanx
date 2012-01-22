package org.brekka.phalanx.model;

import java.util.UUID;

import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;

@Entity
@Table(name = "\"Principal\"")
public class Principal extends IdentifiableEntity {

    @OneToOne
    @JoinColumn(name = "DefaultKeyPair")
    private AsymmetricKeyPair defaultKeyPair;
    
    public Principal() {
        
    }
    
    public Principal(UUID uuid) {
        setId(uuid);
    }

    public AsymmetricKeyPair getDefaultKeyPair() {
        return defaultKeyPair;
    }

    public void setDefaultKeyPair(AsymmetricKeyPair defaultKeyPair) {
        this.defaultKeyPair = defaultKeyPair;
    }

}
