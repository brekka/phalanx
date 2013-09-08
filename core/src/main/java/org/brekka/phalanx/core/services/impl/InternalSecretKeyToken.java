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

import org.brekka.phalanx.core.model.SecretKeyToken;
import org.brekka.phalanx.core.model.SymedCryptoData;
import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.SecretKey;
import org.brekka.phoenix.api.SymmetricCryptoSpec;

class InternalSecretKeyToken implements SecretKeyToken {

    private final SecretKey secretKey;
    
    private SymedCryptoData symedCryptoData;

    public InternalSecretKeyToken(SecretKey secretKey) {
        this(secretKey, null);
    }
    public InternalSecretKeyToken(SecretKey secretKey, SymedCryptoData symedCryptoData) {
        this.secretKey = secretKey;
        this.symedCryptoData = symedCryptoData;
    }
    
    void setSymedCryptoData(SymedCryptoData symedCryptoData) {
        this.symedCryptoData = symedCryptoData;
    }
    
    public SecretKey getSecretKey() {
        return secretKey;
    }
    
    @Override
    public SymedCryptoData getSymedCryptoData() {
        return symedCryptoData;
    }
}
