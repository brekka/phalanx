package org.brekka.phalanx.core.model;

import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import org.brekka.commons.persistence.model.IdentifiableEntity;
import org.hibernate.annotations.Type;

@Entity
@Table(name = "\"Principal\"")
public class Principal implements IdentifiableEntity<UUID>, org.brekka.phalanx.api.model.Principal {

    /**
     * Serial UID
     */
    private static final long serialVersionUID = -4900201815422671490L;
    
    @Id
    @Type(type="pg-uuid")
    @Column(name="ID")
    private UUID id;
    
    @OneToOne
    @JoinColumn(name = "DefaultKeyPair")
    private AsymmetricKeyPair defaultKeyPair;
    public Principal() {
        
    }
    
    public Principal(UUID uuid) {
        setId(uuid);
    }

    
    public final UUID getId() {
        return id;
    }
    
    public final void setId(UUID id) {
        this.id = id;
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
