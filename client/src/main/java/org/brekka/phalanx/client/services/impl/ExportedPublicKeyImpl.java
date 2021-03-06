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

package org.brekka.phalanx.client.services.impl;

import org.brekka.phalanx.api.model.ExportedPublicKey;

/**
 * ExportedPublicKeyImpl
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
class ExportedPublicKeyImpl implements ExportedPublicKey {

    private final byte[] encoded;
    
    private final int cryptoProfile;
    
    /**
     * @param encoded
     * @param cryptoProfile
     */
    public ExportedPublicKeyImpl(byte[] encoded, int cryptoProfile) {
        this.encoded = encoded;
        this.cryptoProfile = cryptoProfile;
    }

    /* (non-Javadoc)
     * @see org.brekka.phalanx.api.model.ExportedPublicKey#getEncoded()
     */
    @Override
    public byte[] getEncoded() {
        return encoded;
    }

    /* (non-Javadoc)
     * @see org.brekka.phalanx.api.model.ExportedPublicKey#getCryptoProfile()
     */
    @Override
    public int getCryptoProfile() {
        return cryptoProfile;
    }

}
