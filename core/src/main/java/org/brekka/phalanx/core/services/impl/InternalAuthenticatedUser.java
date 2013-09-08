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

import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.api.model.Principal;
import org.brekka.phalanx.api.model.PrivateKeyToken;

class InternalAuthenticatedUser implements AuthenticatedPrincipal {
    private final Principal user;

    private final InternalPrivateKeyToken privateKey;

    public InternalAuthenticatedUser(Principal user, InternalPrivateKeyToken privateKey) {
        this.user = user;
        this.privateKey = privateKey;
    }

    @Override
    public Principal getPrincipal() {
        return user;
    }

    @Override
    public PrivateKeyToken getDefaultPrivateKey() {
        return privateKey;
    }
}