package org.brekka.phalanx.model;

import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Id;
import javax.persistence.MappedSuperclass;

import org.hibernate.annotations.Type;

@MappedSuperclass
public abstract class IdentifiableEntity {
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
