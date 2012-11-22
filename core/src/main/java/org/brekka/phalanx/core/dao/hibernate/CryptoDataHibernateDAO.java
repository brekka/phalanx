package org.brekka.phalanx.core.dao.hibernate;

import org.brekka.phalanx.core.dao.CryptoDataDAO;
import org.brekka.phalanx.core.model.CryptoData;
import org.springframework.stereotype.Repository;

@Repository
public class CryptoDataHibernateDAO extends AbstractPhalanxHibernateEntityDAO<CryptoData> implements CryptoDataDAO {

    @Override
    protected Class<CryptoData> type() {
        return CryptoData.class;
    }

}
