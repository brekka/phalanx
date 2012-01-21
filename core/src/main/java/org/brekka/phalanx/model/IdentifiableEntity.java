package org.brekka.phalanx.model;

import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Id;
import javax.persistence.MappedSuperclass;

@MappedSuperclass
public abstract class IdentifiableEntity {
    @Id
    @Column(name="ID")
    private UUID id;

    public final UUID getId() {
        return id;
    }

    public final void setId(UUID id) {
        this.id = id;
    }
}
