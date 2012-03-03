package org.brekka.phalanx.services.impl;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

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

}
