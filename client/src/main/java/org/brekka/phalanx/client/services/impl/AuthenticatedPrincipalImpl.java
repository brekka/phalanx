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

import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.api.model.Principal;
import org.brekka.phalanx.api.model.PrivateKeyToken;

class AuthenticatedPrincipalImpl implements AuthenticatedPrincipal {

    private final byte[] sessionId;
    
    private final Principal principal;
    
    private final PrivateKeyToken defaultPrivateKey;
    
    AuthenticatedPrincipalImpl(Principal principal, byte[] sessionId, byte[] defaultPrivateKeyId) {
        this.principal = principal;
        this.sessionId = sessionId;
        this.defaultPrivateKey = new PrivateKeyTokenImpl(defaultPrivateKeyId, principal.getDefaultKeyPair(), this);
    }

    @Override
    public Principal getPrincipal() {
        return principal;
    }

    @Override
    public PrivateKeyToken getDefaultPrivateKey() {
        return defaultPrivateKey;
    }
    
    public byte[] getSessionId() {
        return sessionId;
    }
}
