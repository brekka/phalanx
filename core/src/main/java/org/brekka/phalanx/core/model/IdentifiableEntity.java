package org.brekka.phalanx.core.model;

import java.io.Serializable;
import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Id;
import javax.persistence.MappedSuperclass;

import org.hibernate.annotations.Type;

@MappedSuperclass
public abstract class IdentifiableEntity implements Serializable {
    
    /**
     * Serial UID
     */
    private static final long serialVersionUID = 4922617741795416005L;
    
    @Id
    @Type(type="pg-uuid")
    @Column(name="ID")
    private UUID id;

    public final UUID getId() {
        return id;
    }

    public final void setId(UUID id) {
        this.id = id;
    }
}
