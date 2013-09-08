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

import java.util.UUID;

import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.core.dao.PrincipalDAO;
import org.brekka.phalanx.core.model.AsymmetricKeyPair;
import org.brekka.phalanx.core.model.Principal;
import org.brekka.phalanx.core.services.AsymmetricCryptoService;
import org.brekka.phalanx.core.services.PrincipalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class PrincipalServiceImpl implements PrincipalService {

    @Autowired
    private PrincipalDAO principalDAO;
    
    @Autowired
    private AsymmetricCryptoService asymmetricCryptoService;
    
    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public AuthenticatedPrincipal authenticate(Principal principal, String password) {
        Principal managedUser = principalDAO.retrieveById(principal.getId());
        AsymmetricKeyPair defaultKeyPair = managedUser.getDefaultKeyPair();
        InternalPrivateKeyToken privateKeyToken = (InternalPrivateKeyToken) asymmetricCryptoService.decrypt(defaultKeyPair, password);
        InternalAuthenticatedUser authenticatedUser = new InternalAuthenticatedUser(managedUser, privateKeyToken);
        return authenticatedUser;
    }
    
    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public Principal createPrincipal(String password) {
        Principal principal = new Principal();
        AsymmetricKeyPair keyPair = asymmetricCryptoService.generateKeyPair(password, principal);
        principal.setDefaultKeyPair(keyPair);
        principalDAO.create(principal);
        return principal;
    }
    
    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public Principal retrieveById(UUID principalId) {
        return principalDAO.retrieveById(principalId);
    }
    
    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void deletePrincipal(UUID principalId) {
        principalDAO.delete(principalId);
    }

}
