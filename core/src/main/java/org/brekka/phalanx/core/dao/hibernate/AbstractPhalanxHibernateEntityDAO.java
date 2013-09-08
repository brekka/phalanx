/*
 * Copyright 2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.brekka.phalanx.core.dao.hibernate;

import java.util.UUID;

import org.brekka.commons.persistence.dao.hibernate.AbstractUniversallyIdentifiableEntityHibernateDAO;
import org.brekka.commons.persistence.model.IdentifiableEntity;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;

public abstract class AbstractPhalanxHibernateEntityDAO<T extends IdentifiableEntity<UUID>> 
                extends AbstractUniversallyIdentifiableEntityHibernateDAO<T>{

    @Autowired
    private SessionFactory phalanxSessionFactory;
    
    @SuppressWarnings("unchecked")
    @Override
    public T retrieveById(UUID entityId) {
        Session session = phalanxSessionFactory.getCurrentSession();
        return (T) session.get(type(), entityId);
    }
    
    protected abstract Class<T> type();

    @Override
    public UUID create(T entity) {
        UUID id = UUID.randomUUID();
        entity.setId(id);
        Session session = phalanxSessionFactory.getCurrentSession();
        session.save(entity);
        return id;
    }

    @Override
    public void update(T entity) {
        Session session = phalanxSessionFactory.getCurrentSession();
        session.update(entity);
    }

    @Override
    public void delete(UUID entityId) {
        Session session = phalanxSessionFactory.getCurrentSession();
        Object toDelete = session.get(type(), entityId);
        session.delete(toDelete);
    }

    protected final Session getCurrentSession() {
        return phalanxSessionFactory.getCurrentSession();
    }
}
