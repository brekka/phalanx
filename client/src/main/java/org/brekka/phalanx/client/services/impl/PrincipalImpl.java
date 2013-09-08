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

import java.util.UUID;

import org.brekka.phalanx.api.model.KeyPair;
import org.brekka.phalanx.api.model.Principal;

class PrincipalImpl implements Principal {

    private final UUID id;
    
    private final KeyPair defaultKeyPair;
    
    PrincipalImpl(UUID id, KeyPair defaultKeyPair) {
        this.id = id;
        this.defaultKeyPair = defaultKeyPair;
    }

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public KeyPair getDefaultKeyPair() {
        return defaultKeyPair;
    }

}
