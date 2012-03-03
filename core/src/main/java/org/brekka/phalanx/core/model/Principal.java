package org.brekka.phalanx.core.model;

import java.util.UUID;

import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;

@Entity
@Table(name = "\"Principal\"")
public class Principal extends IdentifiableEntity implements org.brekka.phalanx.api.model.Principal {

    /**
     * Serial UID
     */
    private static final long serialVersionUID = -4900201815422671490L;
    
    @OneToOne
    @JoinColumn(name = "DefaultKeyPair")
    private AsymmetricKeyPair defaultKeyPair;
    
    public Principal() {
        
    }
    
    public Principal(UUID uuid) {
        setId(uuid);
    }

    /* (non-Javadoc)
     * @see org.brekka.phalanx.model.IPrincipal#getDefaultKeyPair()
     */
    @Override
    public AsymmetricKeyPair getDefaultKeyPair() {
        return defaultKeyPair;
    }

    public void setDefaultKeyPair(AsymmetricKeyPair defaultKeyPair) {
        this.defaultKeyPair = defaultKeyPair;
    }

}
