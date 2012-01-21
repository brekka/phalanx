package org.brekka.phalanx.dao.hibernate;

import org.brekka.phalanx.dao.AsymmetricKeyPairDAO;
import org.brekka.phalanx.model.AsymmetricKeyPair;
import org.springframework.stereotype.Repository;

@Repository
public class AsymmetricKeyPairHibernateDAO extends AbstractHibernateEntityDAO<AsymmetricKeyPair> implements AsymmetricKeyPairDAO {


    @Override
    protected Class<AsymmetricKeyPair> type() {
        return AsymmetricKeyPair.class;
    }

}
