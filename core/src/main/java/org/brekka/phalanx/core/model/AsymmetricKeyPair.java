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
import javax.persistence.ManyToOne;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import org.brekka.commons.persistence.model.IdentifiableEntity;
import org.brekka.phalanx.api.model.KeyPair;
import org.brekka.phalanx.core.PhalanxConstants;
import org.hibernate.annotations.Type;

/**
 * Defines the storage of public/private key pair. The private key data will always be unique to a given
 * {@link AsymmetricKeyPair} instance. The public key data may be shared among several {@link AsymmetricKeyPair}
 * instances.
 * 
 * @author Andrew Taylor
 */
@Entity
@Table(name="`AsymmetricKeyPair`", schema=PhalanxConstants.SCHEMA)
public class AsymmetricKeyPair implements IdentifiableEntity<UUID>, KeyPair {

    /**
     * Serial UID
     */
    private static final long serialVersionUID = 2584665854047069047L;

    @Id
    @Type(type="pg-uuid")
    @Column(name="`ID`")
    private UUID id;

    /**
     * The private key data. This should always be an instance of on the {@link CryptoData} sub-types as private keys
     * need to be protected. Can be null which indicates that this is an an anonymous key pair containing only a
     * public key.
     */
    @OneToOne
    @JoinColumn(name="`PrivateKeyID`")
    private CryptoData privateKey;

    /**
     * The public key data, which should just be a plain {@link CryptoData} as it does not need to be encrypted.
     */
    @ManyToOne
    @JoinColumn(name="`PublicKeyID`", nullable=false)
    private CryptoData publicKey;




    public AsymmetricKeyPair() {
    }

    public AsymmetricKeyPair(final UUID id) {
        setId(id);
    }

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public void setId(final UUID id) {
        this.id = id;
    }

    public CryptoData getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(final CryptoData privateKey) {
        this.privateKey = privateKey;
    }

    public CryptoData getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(final CryptoData publicKey) {
        this.publicKey = publicKey;
    }
}
