package org.brekka.phalanx.core.dao.hibernate;

import org.brekka.phalanx.core.dao.AsymmetricKeyPairDAO;
import org.brekka.phalanx.core.model.AsymmetricKeyPair;
import org.springframework.stereotype.Repository;

@Repository
public class AsymmetricKeyPairHibernateDAO extends AbstractPhalanxHibernateEntityDAO<AsymmetricKeyPair> implements AsymmetricKeyPairDAO {


    @Override
    protected Class<AsymmetricKeyPair> type() {
        return AsymmetricKeyPair.class;
    }

}
