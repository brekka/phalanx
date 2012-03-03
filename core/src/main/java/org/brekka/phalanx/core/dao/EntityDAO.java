package org.brekka.phalanx.core.dao;

import java.util.UUID;

import org.brekka.phalanx.core.model.IdentifiableEntity;

public interface EntityDAO<T extends IdentifiableEntity> {

    T retrieveById(UUID entityId);
    
    UUID create(T entity);
    
    void update(T entity);
    
    void delete(UUID entityId);
}
