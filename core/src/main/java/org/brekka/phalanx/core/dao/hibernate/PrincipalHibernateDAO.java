package org.brekka.phalanx.core.dao.hibernate;

import org.brekka.phalanx.core.dao.PrincipalDAO;
import org.brekka.phalanx.core.model.Principal;
import org.springframework.stereotype.Repository;

@Repository
public class PrincipalHibernateDAO extends AbstractHibernateEntityDAO<Principal> implements PrincipalDAO {

    @Override
    protected Class<Principal> type() {
        return Principal.class;
    }

}
