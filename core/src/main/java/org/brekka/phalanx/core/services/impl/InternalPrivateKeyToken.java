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

package org.brekka.phalanx.core.services.impl;


import org.brekka.phalanx.api.model.PrivateKeyToken;
import org.brekka.phalanx.core.model.AsymmetricKeyPair;
import org.brekka.phalanx.core.model.CryptoData;
import org.brekka.phoenix.api.PrivateKey;

class InternalPrivateKeyToken implements PrivateKeyToken {
    
    private transient final PrivateKey privateKey;
    
    private transient AsymmetricKeyPair asymmetricKeyPair;
    
    /**
     * Needed to assign the private key to others.
     */
    private transient InternalSecretKeyToken secretKey;
    
    public InternalPrivateKeyToken(PrivateKey privateKey, AsymmetricKeyPair asymmetricKeyPair) {
        this.privateKey = privateKey;
        this.asymmetricKeyPair = asymmetricKeyPair;
    }
    
    public InternalPrivateKeyToken(PrivateKey privateKey) {
        this(privateKey, null);
        AsymmetricKeyPair keyPair = new AsymmetricKeyPair();
        CryptoData stubPrivateKey = new CryptoData();
        keyPair.setPrivateKey(stubPrivateKey);
        stubPrivateKey.setProfile(privateKey.getCryptoProfile().getNumber());
        this.asymmetricKeyPair = keyPair;
    }

    @Override
    public AsymmetricKeyPair getKeyPair() {
        return asymmetricKeyPair;
    }
    
    void setAsymetricKeyPair(AsymmetricKeyPair asymetricKeyPair) {
        this.asymmetricKeyPair = asymetricKeyPair;
    }
    
    void setSecretKey(InternalSecretKeyToken secretKey) {
        this.secretKey = secretKey;
    }
    
    PrivateKey getPrivateKey() {
        return privateKey;
    }
    
    InternalSecretKeyToken getSecretKey() {
        return secretKey;
    }
}