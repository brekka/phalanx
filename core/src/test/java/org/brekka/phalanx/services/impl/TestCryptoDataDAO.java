package org.brekka.phalanx.services.impl;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.persistence.LockModeType;

import org.brekka.phalanx.core.dao.CryptoDataDAO;
import org.brekka.phalanx.core.model.CryptoData;

public class TestCryptoDataDAO implements CryptoDataDAO {

    private Map<UUID, CryptoData> map = new HashMap<UUID, CryptoData>();
    
    @Override
    public CryptoData retrieveById(UUID entityId) {
        return map.get(entityId);
    }

    @Override
    public UUID create(CryptoData entity) {
        UUID uuid = UUID.randomUUID();
        entity.setId(uuid);
        map.put(uuid, entity);
        return uuid;
    }

    @Override
    public void update(CryptoData entity) {
        
    }

    @Override
    public void delete(UUID entityId) {
        map.remove(entityId);
    }

    /* (non-Javadoc)
     * @see org.brekka.commons.persistence.dao.EntityDAO#retrieveById(java.io.Serializable, javax.persistence.LockModeType)
     */
    @Override
    public CryptoData retrieveById(UUID entityId, LockModeType lockMode) {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see org.brekka.commons.persistence.dao.EntityDAO#retrieveById(java.io.Serializable, javax.persistence.LockModeType, int, java.util.concurrent.TimeUnit)
     */
    @Override
    public CryptoData retrieveById(UUID entityId, LockModeType lockMode, int timeout, TimeUnit timeUnit) {
        // TODO Auto-generated method stub
        return null;
    }

}
