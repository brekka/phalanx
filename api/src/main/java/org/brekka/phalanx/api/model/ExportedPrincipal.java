/*
 * Copyright 2016 the original author or authors.
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

package org.brekka.phalanx.api.model;

import java.io.Serializable;
import java.util.UUID;

/**
 * TODO Description of ExportedPrincipal
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
public final class ExportedPrincipal implements Serializable {
    /**
     * Serial UID
     */
    private static final long serialVersionUID = 2120952772879347355L;

    private final int cryptoProfileId;

    private final UUID principalId;

    private final UUID symKeyId;

    private final byte[] iv;

    private final byte[] cipherText;


    public ExportedPrincipal(final int cryptoProfileId, final UUID principalId, final UUID symKeyId, final byte[] iv, final byte[] cipherText) {
        this.cryptoProfileId = cryptoProfileId;
        this.principalId = principalId;
        this.symKeyId = symKeyId;
        this.iv = iv;
        this.cipherText = cipherText;
    }


    public byte[] getIv() {
        return iv;
    }

    public int getCryptoProfileId() {
        return cryptoProfileId;
    }

    public UUID getPrincipalId() {
        return principalId;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public UUID getSymKeyId() {
        return symKeyId;
    }
}
