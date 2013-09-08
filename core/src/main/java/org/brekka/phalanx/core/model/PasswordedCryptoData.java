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
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

import org.brekka.phalanx.api.model.CryptedData;

/**
 * A piece of content that has been encypted using a password based encryption scheme.
 * 
 * @author Andrew Taylor
 */
@Entity
@DiscriminatorValue("Password")
public class PasswordedCryptoData extends CryptoData implements CryptedData {
    
    /**
     * Serial UID
     */
    private static final long serialVersionUID = 7900986833181045388L;
    
    
    @Column(name="`Salt`")
    private byte[] salt;
    
    @Column(name="`Iterations`")
    private Integer iterations;
    
    public PasswordedCryptoData() {
    }
    
    public PasswordedCryptoData(UUID id) {
        setId(id);
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    /**
     * @return the iterations
     */
    public Integer getIterations() {
        return iterations;
    }

    /**
     * @param iterations the iterations to set
     */
    public void setIterations(Integer iterations) {
        this.iterations = iterations;
    }
}
