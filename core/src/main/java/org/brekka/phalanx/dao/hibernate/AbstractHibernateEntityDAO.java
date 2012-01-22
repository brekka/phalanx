package org.brekka.phalanx.dao.hibernate;

import java.util.UUID;

import org.brekka.phalanx.dao.EntityDAO;
import org.brekka.phalanx.model.IdentifiableEntity;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;

public abstract class AbstractHibernateEntityDAO<T extends IdentifiableEntity> implements EntityDAO<T> {

    @Autowired
    private SessionFactory sessionFactory;
    
    @SuppressWarnings("unchecked")
    @Override
    public T retrieveById(UUID entityId) {
        Session session = sessionFactory.getCurrentSession();
        return (T) session.get(type(), entityId);
    }
    
    protected abstract Class<T> type();

    @Override
    public UUID create(T entity) {
        UUID id = UUID.randomUUID();
        entity.setId(id);
        Session session = sessionFactory.getCurrentSession();
        session.save(entity);
        return id;
    }

    @Override
    public void update(T entity) {
        Session session = sessionFactory.getCurrentSession();
        session.update(entity);
    }

    @Override
    public void delete(UUID entityId) {
        Session session = sessionFactory.getCurrentSession();
        Object toDelete = session.get(type(), entityId);
        session.delete(toDelete);
    }

    protected final Session getCurrentSession() {
        return sessionFactory.getCurrentSession();
    }
}
