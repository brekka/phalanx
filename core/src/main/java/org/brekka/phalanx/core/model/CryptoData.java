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
import javax.persistence.DiscriminatorColumn;
import javax.persistence.DiscriminatorType;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.Table;

import org.brekka.commons.persistence.model.IdentifiableEntity;
import org.brekka.phalanx.core.PhalanxConstants;
import org.hibernate.annotations.Type;

/**
 * The implementation describes the mechanism used to encrypt the payload data, not the data itself which could be anything.
 * 
 * @author Andrew Taylor
 */
@Entity
@Inheritance(strategy=InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name="`Type`", discriminatorType=DiscriminatorType.STRING, length=8)
@Table(name="`CryptoData`", schema=PhalanxConstants.SCHEMA)
@DiscriminatorValue("Plain")
public class CryptoData implements IdentifiableEntity<UUID> {
    
    /**
     * Serial UID
     */
    private static final long serialVersionUID = 118372503696946797L;
    
    @Id
    @Type(type="pg-uuid")
    @Column(name="`ID`")
    private UUID id;

    @Column(name="`Data`", nullable=false)
    private byte[] data;
    
    @Column(name="`Profile`")
    private int profile;

    public final UUID getId() {
        return id;
    }

    public final void setId(UUID id) {
        this.id = id;
    }
    
    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public int getProfile() {
        return profile;
    }

    public void setProfile(int profile) {
        this.profile = profile;
    }
}
