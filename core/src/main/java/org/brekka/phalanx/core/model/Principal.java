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

package org.brekka.phalanx.core.model;

import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import org.brekka.commons.persistence.model.IdentifiableEntity;
import org.brekka.phalanx.core.PhalanxConstants;
import org.hibernate.annotations.Type;

@Entity
@Table(name = "`Principal`", schema=PhalanxConstants.SCHEMA)
public class Principal implements IdentifiableEntity<UUID>, org.brekka.phalanx.api.model.Principal {

    /**
     * Serial UID
     */
    private static final long serialVersionUID = -4900201815422671490L;
    
    @Id
    @Type(type="pg-uuid")
    @Column(name="`ID`")
    private UUID id;
    
    @OneToOne
    @JoinColumn(name = "`DefaultKeyPair`")
    private AsymmetricKeyPair defaultKeyPair;
    
    
    public Principal() {
        
    }
    
    public Principal(UUID uuid) {
        setId(uuid);
    }

    
    public final UUID getId() {
        return id;
    }
    
    public final void setId(UUID id) {
        this.id = id;
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phalanx.model.IPrincipal#getDefaultKeyPair()
     */
    @Override
    public AsymmetricKeyPair getDefaultKeyPair() {
        return defaultKeyPair;
    }

    public void setDefaultKeyPair(AsymmetricKeyPair defaultKeyPair) {
        this.defaultKeyPair = defaultKeyPair;
    }

}
