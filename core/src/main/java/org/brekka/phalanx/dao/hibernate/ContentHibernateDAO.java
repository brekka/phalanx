package org.brekka.phalanx.dao.hibernate;

import org.brekka.phalanx.dao.ContentDAO;
import org.brekka.phalanx.model.Content;
import org.springframework.stereotype.Repository;

@Repository
public class ContentHibernateDAO extends AbstractHibernateEntityDAO<Content> implements ContentDAO {

    @Override
    protected Class<Content> type() {
        return Content.class;
    }

}
