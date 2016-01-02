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

import org.brekka.phalanx.api.PhalanxErrorCode;
import org.brekka.phalanx.api.PhalanxException;
import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.api.model.CryptedData;
import org.brekka.phalanx.api.model.ExportedPrincipal;
import org.brekka.phalanx.api.model.ExportedPublicKey;
import org.brekka.phalanx.api.model.KeyPair;
import org.brekka.phalanx.api.model.PrivateKeyToken;
import org.brekka.phalanx.api.services.PhalanxService;
import org.brekka.phalanx.core.dao.CryptoDataDAO;
import org.brekka.phalanx.core.model.AsymedCryptoData;
import org.brekka.phalanx.core.model.AsymmetricKeyPair;
import org.brekka.phalanx.core.model.CryptoData;
import org.brekka.phalanx.core.model.PasswordedCryptoData;
import org.brekka.phalanx.core.model.Principal;
import org.brekka.phalanx.core.services.AsymmetricCryptoService;
import org.brekka.phalanx.core.services.PasswordBasedCryptoService;
import org.brekka.phalanx.core.services.PrincipalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.w3c.dom.Document;

/**
 *
 * @author Andrew Taylor
 */
@Service
@Transactional
public class PhalanxServiceImpl implements PhalanxService {

    @Autowired
    private PasswordBasedCryptoService passwordBasedCryptoService;

    @Autowired
    private AsymmetricCryptoService asymmetricCryptoService;

    @Autowired
    private PrincipalService principalService;

    @Autowired
    private CryptoDataDAO cryptoDataDAO;


    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public CryptedData asymEncrypt(final byte[] data, final KeyPair keyPair) {
        AsymmetricKeyPair asymKeyPair = this.asymmetricCryptoService.retrieveKeyPair(keyPair.getId());
        AsymedCryptoData asymedCryptoData = this.asymmetricCryptoService.encrypt(data, asymKeyPair);
        return asymedCryptoData;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public CryptedData asymEncrypt(final byte[] data, final org.brekka.phalanx.api.model.Principal recipientPrincipal) {
        Principal principal = this.principalService.retrieveById(recipientPrincipal.getId());
        AsymmetricKeyPair defaultKeyPair = principal.getDefaultKeyPair();
        AsymmetricKeyPair asymKeyPair = this.asymmetricCryptoService.retrieveKeyPair(defaultKeyPair.getId());
        AsymedCryptoData asymedCryptoData = this.asymmetricCryptoService.encrypt(data, asymKeyPair);
        return asymedCryptoData;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public byte[] asymDecrypt(final CryptedData asymedCryptoDataId, final PrivateKeyToken privateKeyToken) {
        AsymedCryptoData dataItem = retrieveDataItem(asymedCryptoDataId, AsymedCryptoData.class);
        byte[] data = this.asymmetricCryptoService.decrypt(dataItem, privateKeyToken, byte[].class);
        return data;
    }



    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public CryptedData pbeEncrypt(final byte[] data, final String password) {
        PasswordedCryptoData cryptoData = this.passwordBasedCryptoService.encrypt(data, password);
        return cryptoData;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public byte[] pbeDecrypt(final CryptedData passwordedCryptoData, final String password) {
        PasswordedCryptoData dataItem = retrieveDataItem(passwordedCryptoData, PasswordedCryptoData.class);
        byte[] data = this.passwordBasedCryptoService.decrypt(dataItem, password, byte[].class);
        return data;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public PrivateKeyToken decryptKeyPair(final KeyPair keyPairIn, final PrivateKeyToken privateKeyToken) {
        AsymmetricKeyPair keyPair = this.asymmetricCryptoService.retrieveKeyPair(keyPairIn.getId());
        PrivateKeyToken nextPrivateKeyToken = this.asymmetricCryptoService.decrypt(keyPair, privateKeyToken);
        return nextPrivateKeyToken;
    }



    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public KeyPair generateKeyPair(final KeyPair protectedByKeyPair, final org.brekka.phalanx.api.model.Principal ownerPrincipal) {
        AsymmetricKeyPair keyPair = this.asymmetricCryptoService.retrieveKeyPair(protectedByKeyPair.getId());
        Principal principal = null;
        if (ownerPrincipal != null) {
            principal = this.principalService.retrieveById(ownerPrincipal.getId());
        }
        AsymmetricKeyPair newKeyPair = this.asymmetricCryptoService.generateKeyPair(keyPair, principal);
        return newKeyPair;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public KeyPair generateKeyPair(final KeyPair protectedByKeyPair) {
        return generateKeyPair(protectedByKeyPair, null);
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public KeyPair cloneKeyPairPublic(final KeyPair protectedByKeyPair) {
        AsymmetricKeyPair keyPair = this.asymmetricCryptoService.retrieveKeyPair(protectedByKeyPair.getId());
        AsymmetricKeyPair newKeyPair = this.asymmetricCryptoService.cloneKeyPairPublic(keyPair);
        return newKeyPair;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public KeyPair assignKeyPair(final PrivateKeyToken privateKeyToken, final org.brekka.phalanx.api.model.Principal assignToPrincipalIn) {
        Principal assignToPrincipal = this.principalService.retrieveById(assignToPrincipalIn.getId());
        AsymmetricKeyPair newKeyPair = this.asymmetricCryptoService.assignKeyPair(privateKeyToken, assignToPrincipal);
        return newKeyPair;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public KeyPair assignKeyPair(final PrivateKeyToken privateKeyToken, final KeyPair assignToKeyPair) {
        AsymmetricKeyPair keyPair = this.asymmetricCryptoService.retrieveKeyPair(assignToKeyPair.getId());
        AsymmetricKeyPair newKeyPair = this.asymmetricCryptoService.assignKeyPair(privateKeyToken, keyPair);
        return newKeyPair;
    }

    @Override
    public ExportedPublicKey retrievePublicKey(final KeyPair keyPair) {
        AsymmetricKeyPair asymKeyPair = this.asymmetricCryptoService.retrieveKeyPair(keyPair.getId());
        CryptoData publicKey = asymKeyPair.getPublicKey();
        return new ExportedPublicKeyImpl(publicKey.getData(), publicKey.getProfile());
    }

    @Override
    public ExportedPublicKey retrievePublicKey(final org.brekka.phalanx.api.model.Principal principal) {
        Principal thePrincipal = this.principalService.retrieveById(principal.getId());
        AsymmetricKeyPair keyPair = thePrincipal.getDefaultKeyPair();
        return retrievePublicKey(keyPair);
    }

    @Override
    public Document sign(final Document document, final PrivateKeyToken privateKeyToken) {
        return this.asymmetricCryptoService.sign(document, privateKeyToken);
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void deleteCryptedData(final CryptedData cryptoDataItem) {
        this.cryptoDataDAO.delete(cryptoDataItem.getId());
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void deleteKeyPair(final KeyPair keyPair) {
        this.asymmetricCryptoService.deleteKeyPair(keyPair.getId());
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public org.brekka.phalanx.api.model.Principal createPrincipal(final String password) {
        Principal principal = this.principalService.createPrincipal(password);
        return principal;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void deletePrincipal(final org.brekka.phalanx.api.model.Principal principal) {
        this.principalService.deletePrincipal(principal.getId());
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public AuthenticatedPrincipal authenticate(final org.brekka.phalanx.api.model.Principal principal, final String password) {
        Principal corePrincipal = this.principalService.retrieveById(principal.getId());
        AuthenticatedPrincipal authenticatedPrincipal = this.principalService.authenticate(corePrincipal, password);
        return authenticatedPrincipal;
    }

    @Override
    public void logout(final AuthenticatedPrincipal authenticatedPrincipal) {
        // Don't need to do anything, maybe log something
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void changePassword(final org.brekka.phalanx.api.model.Principal principalIn, final String currentPassword, final String newPassword) {
        Principal principal = this.principalService.retrieveById(principalIn.getId());
        AsymmetricKeyPair keyPair = principal.getDefaultKeyPair();
        CryptoData privateKey = keyPair.getPrivateKey();
        if (privateKey instanceof PasswordedCryptoData == false) {
            throw new PhalanxException(PhalanxErrorCode.CP209,
                    "Key pair '%s' private key is not password protected", keyPair.getId());
        }
        PasswordedCryptoData passwordedCryptoData = (PasswordedCryptoData) privateKey;
        InternalSecretKeyToken secretKeyToken = this.passwordBasedCryptoService.decrypt(
                passwordedCryptoData, currentPassword, InternalSecretKeyToken.class);

        PasswordedCryptoData privateKeyData = this.passwordBasedCryptoService.encrypt(secretKeyToken, newPassword);

        this.asymmetricCryptoService.replacePrivateKey(keyPair, privateKeyData);
    }

    @Override
    @Transactional
    public ExportedPrincipal exportPrincipal(final AuthenticatedPrincipal principal, final byte[] secret) {
        return principalService.export(principal, secret);
    }

    @Override
    @Transactional
    public AuthenticatedPrincipal importPrincipal(final ExportedPrincipal exportedPrincipal, final byte[] secret) {
        return principalService.restore(exportedPrincipal, secret);
    }

    @SuppressWarnings("unchecked")
    private <T extends CryptoData> T retrieveDataItem(final CryptedData cryptedData, final Class<T> expectedType) {
        CryptoData cryptoData = this.cryptoDataDAO.retrieveById(cryptedData.getId());
        if (cryptoData == null) {
            throw new PhalanxException(PhalanxErrorCode.CP601, "Crypted data item with id '%s' does not exist",
                    cryptedData.getId());
        }
        if (!expectedType.isAssignableFrom(cryptoData.getClass())) {
            throw new PhalanxException(PhalanxErrorCode.CP600, "Expected crypto data type %s, found %s",
                    expectedType.getSimpleName(), cryptoData.getClass().getSimpleName());
        }
        return (T) cryptoData;
    }
}
