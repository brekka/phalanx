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
import org.brekka.phalanx.api.model.ExportedPrincipal;
import org.brekka.phalanx.core.dao.CryptoDataDAO;
import org.brekka.phalanx.core.dao.PrincipalDAO;
import org.brekka.phalanx.core.model.AsymmetricKeyPair;
import org.brekka.phalanx.core.model.Principal;
import org.brekka.phalanx.core.model.SymedCryptoData;
import org.brekka.phalanx.core.services.AsymmetricCryptoService;
import org.brekka.phalanx.core.services.PrincipalService;
import org.brekka.phalanx.core.services.SymmetricCryptoService;
import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.CryptoResult;
import org.brekka.phoenix.api.DerivedKey;
import org.brekka.phoenix.api.SecretKey;
import org.brekka.phoenix.api.SymmetricCryptoSpec;
import org.brekka.phoenix.api.services.CryptoProfileService;
import org.brekka.phoenix.api.services.DerivedKeyCryptoService;
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
    private CryptoDataDAO cryptoDataDAO;

    @Autowired
    private AsymmetricCryptoService asymmetricCryptoService;

    @Autowired
    private SymmetricCryptoService symmetricCryptoService;

    @Autowired
    private org.brekka.phoenix.api.services.SymmetricCryptoService phoenixSymmetricCryptoService;



    @Autowired
    private DerivedKeyCryptoService derivedKeyCryptoService;

    @Autowired
    private CryptoProfileService cryptoProfileService;

    @Override
    @Transactional(propagation = Propagation.SUPPORTS)
    public AuthenticatedPrincipal authenticate(final Principal principal, final String password) {
        Principal managedUser = principalDAO.retrieveById(principal.getId());
        AsymmetricKeyPair defaultKeyPair = managedUser.getDefaultKeyPair();
        InternalPrivateKeyToken privateKeyToken = (InternalPrivateKeyToken) asymmetricCryptoService
                .decrypt(defaultKeyPair, password);
        InternalAuthenticatedUser authenticatedUser = new InternalAuthenticatedUser(managedUser, privateKeyToken);
        return authenticatedUser;
    }

    @Override
    @Transactional
    public Principal createPrincipal(final String password) {
        Principal principal = new Principal();
        AsymmetricKeyPair keyPair = asymmetricCryptoService.generateKeyPair(password, principal);
        principal.setDefaultKeyPair(keyPair);
        principalDAO.create(principal);
        return principal;
    }

    @Override
    @Transactional(readOnly=true)
    public Principal retrieveById(final UUID principalId) {
        return principalDAO.retrieveById(principalId);
    }

    @Override
    @Transactional
    public void deletePrincipal(final UUID principalId) {
        principalDAO.delete(principalId);
    }

    @Override
    public ExportedPrincipal export(final AuthenticatedPrincipal principal, final byte[] secret) {
        InternalAuthenticatedUser internal = (InternalAuthenticatedUser) principal;
        CryptoProfile cryptoProfile = cryptoProfileService.retrieveDefault();
        DerivedKey derivedKey = derivedKeyCryptoService.apply(secret, cryptoProfile);
        SymmetricCryptoSpec symmetricCryptoSpec = phoenixSymmetricCryptoService.toSymmetricCryptoSpec(derivedKey);
        InternalPrivateKeyToken privateKey = (InternalPrivateKeyToken) internal.getDefaultPrivateKey();
        InternalSecretKeyToken secretKey = privateKey.getSecretKey();
        UUID symKeyId = secretKey.getSymedCryptoData().getId();
        UUID principalId = principal.getPrincipal().getId();
        byte[] key = secretKey.getSecretKey().getEncoded();
        CryptoResult<SymmetricCryptoSpec> result = phoenixSymmetricCryptoService.encrypt(key, symmetricCryptoSpec);
        ExportedPrincipal exportedPrincipal = new ExportedPrincipal(cryptoProfile.getNumber(),
                principalId, symKeyId, derivedKey.getSalt(), result.getCipherText());
        return exportedPrincipal;
    }

    @Override
    public AuthenticatedPrincipal restore(final ExportedPrincipal exportedPrincipal, final byte[] secret) {
        byte[] cipherText = exportedPrincipal.getCipherText();
        CryptoProfile cryptoProfile = cryptoProfileService.retrieveProfile(exportedPrincipal.getCryptoProfileId());
        DerivedKey derivedKey = derivedKeyCryptoService.apply(secret, exportedPrincipal.getIv(), null, cryptoProfile);
        SymmetricCryptoSpec symmetricCryptoSpec = phoenixSymmetricCryptoService.toSymmetricCryptoSpec(derivedKey);
        byte[] secretKeyBytes = phoenixSymmetricCryptoService.decrypt(cipherText, symmetricCryptoSpec);
        Principal principal = principalDAO.retrieveById(exportedPrincipal.getPrincipalId());
        AsymmetricKeyPair keyPair = principal.getDefaultKeyPair();
        SecretKey secretKey = phoenixSymmetricCryptoService.toSecretKey(secretKeyBytes, cryptoProfile);
        InternalSecretKeyToken internalSecretKeyToken = new InternalSecretKeyToken(secretKey);

        UUID symDataId = exportedPrincipal.getSymKeyId();
        SymedCryptoData symedCryptoData = (SymedCryptoData) cryptoDataDAO.retrieveById(symDataId);
        InternalPrivateKeyToken privateKeyToken = symmetricCryptoService.decrypt(symedCryptoData, internalSecretKeyToken, InternalPrivateKeyToken.class);
        privateKeyToken.setSecretKey(internalSecretKeyToken);
        privateKeyToken.setAsymetricKeyPair(keyPair);

        InternalAuthenticatedUser internal = new InternalAuthenticatedUser(principal, privateKeyToken);
        return internal;
    }

}
