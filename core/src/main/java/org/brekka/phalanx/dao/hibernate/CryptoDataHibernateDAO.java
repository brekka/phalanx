package org.brekka.phalanx.dao.hibernate;

import org.brekka.phalanx.dao.CryptoDataDAO;
import org.brekka.phalanx.model.CryptoData;
import org.springframework.stereotype.Repository;

@Repository
public class CryptoDataHibernateDAO extends AbstractHibernateEntityDAO<CryptoData> implements CryptoDataDAO {

    @Override
    protected Class<CryptoData> type() {
        return CryptoData.class;
    }

}
