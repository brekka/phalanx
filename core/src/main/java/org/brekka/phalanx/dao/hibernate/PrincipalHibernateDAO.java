package org.brekka.phalanx.dao.hibernate;

import org.brekka.phalanx.dao.PrincipalDAO;
import org.brekka.phalanx.model.Principal;
import org.springframework.stereotype.Repository;

@Repository
public class PrincipalHibernateDAO extends AbstractHibernateEntityDAO<Principal> implements PrincipalDAO {

    @Override
    protected Class<Principal> type() {
        return Principal.class;
    }

}
