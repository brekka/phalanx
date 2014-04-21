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

import org.brekka.phalanx.api.PhalanxErrorCode;
import org.brekka.phalanx.api.PhalanxException;
import org.brekka.phalanx.api.model.PrivateKeyToken;
import org.brekka.phalanx.core.dao.AsymmetricKeyPairDAO;
import org.brekka.phalanx.core.dao.CryptoDataDAO;
import org.brekka.phalanx.core.dao.PrincipalDAO;
import org.brekka.phalanx.core.model.AsymedCryptoData;
import org.brekka.phalanx.core.model.AsymmetricKeyPair;
import org.brekka.phalanx.core.model.CryptoData;
import org.brekka.phalanx.core.model.PasswordedCryptoData;
import org.brekka.phalanx.core.model.Principal;
import org.brekka.phalanx.core.model.SymedCryptoData;
import org.brekka.phalanx.core.services.AsymmetricCryptoService;
import org.brekka.phalanx.core.services.PasswordBasedCryptoService;
import org.brekka.phalanx.core.services.SymmetricCryptoService;
import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.CryptoResult;
import org.brekka.phoenix.api.Key;
import org.brekka.phoenix.api.KeyPair;
import org.brekka.phoenix.api.PrivateKey;
import org.brekka.phoenix.api.PublicKey;
import org.brekka.phoenix.core.PhoenixException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.w3c.dom.Document;

@Service
@Transactional
public class AsymmetricCryptoServiceImpl extends AbstractCryptoService implements AsymmetricCryptoService {

    @Autowired
    private CryptoDataDAO cryptoDataDAO;

    @Autowired
    private AsymmetricKeyPairDAO asymetricKeyPairDAO;

    @Autowired
    private PasswordBasedCryptoService passwordBasedCryptoService;

    @Autowired
    private SymmetricCryptoService symmetricCryptoService;

    @Autowired
    private PrincipalDAO principalDAO;


    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public <T> T decrypt(AsymedCryptoData cryptoData, final PrivateKeyToken privateKeyToken, final Class<T> expectedType) {
        if (privateKeyToken == null) {
            throw new NullPointerException("No private key token supplied");
        }
        cryptoData = (AsymedCryptoData) this.cryptoDataDAO.retrieveById(cryptoData.getId());

        CryptoProfile profile = this.cryptoProfileService.retrieveProfile(cryptoData.getProfile());
        InternalPrivateKeyToken ipkt = narrow(privateKeyToken);
        PrivateKey privateKey = ipkt.getPrivateKey();

        AsymmetricKeyPair dataKeyPair = cryptoData.getKeyPair();
        AsymmetricKeyPair incomingkeyPair = ipkt.getKeyPair();
        // Public keys should always match, even if it is not the same keyPair.
        if (!dataKeyPair.getPublicKey().getId().equals(incomingkeyPair.getPublicKey().getId())) {
            throw new PhalanxException(PhalanxErrorCode.CP204,
                    "The supplied private key '%s' (public key '%s') does not match that required to decrypt the keyPair '%s' (public key '%s').",
                    incomingkeyPair.getPrivateKey().getId(), incomingkeyPair.getPublicKey().getId(), dataKeyPair.getId(), dataKeyPair.getPublicKey().getId());
        }

        byte[] data;
        try {
            data = this.phoenixAsymmetric.decrypt(cryptoData.getData(), privateKey);
        } catch (PhoenixException e) {
            throw new PhalanxException(PhalanxErrorCode.CP211, e,
                    "Failed to decrypt data for CryptoData '%s'",
                    cryptoData.getId());
        }
        return toType(data, expectedType, cryptoData.getId(), profile);
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void replacePrivateKey(final AsymmetricKeyPair keyPair, final PasswordedCryptoData newPrivateKeyData) {
        CryptoData originalPrivateKey = keyPair.getPrivateKey();
        keyPair.setPrivateKey(newPrivateKeyData);
        this.asymetricKeyPairDAO.update(keyPair);
        // Delete the original private key
        this.cryptoDataDAO.delete(originalPrivateKey.getId());
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public AsymedCryptoData encrypt(final Object obj, AsymmetricKeyPair keyPair) {
        // Resolve the key pair from persistent storage (could just be id)
        keyPair = this.asymetricKeyPairDAO.retrieveById(keyPair.getId());

        CryptoData publicKeyData = keyPair.getPublicKey();
        PublicKey publicKey = toPublicKey(publicKeyData);
        byte[] data = toBytes(obj);

        CryptoProfile profile = publicKey.getCryptoProfile();

        byte[] cipherData;
        try {
            CryptoResult<PublicKey> cryptoResult = this.phoenixAsymmetric.encrypt(data, publicKey);
            cipherData = cryptoResult.getCipherText();
        } catch (PhoenixException e) {
            throw new PhalanxException(PhalanxErrorCode.CP212, e,
                    "Failed to encrypt data from object of type '%s' using key pair '%s'",
                    obj.getClass().getName(), keyPair.getId());
        }

        AsymedCryptoData encryptedData = new AsymedCryptoData();
        encryptedData.setData(cipherData);
        encryptedData.setKeyPair(keyPair);
        encryptedData.setProfile(profile.getNumber());
        this.cryptoDataDAO.create(encryptedData);
        return encryptedData;
    }

    @Override
    public void delete(final UUID cryptoKeyId) {
        this.cryptoDataDAO.delete(cryptoKeyId);
    }


    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public PrivateKeyToken decrypt(AsymmetricKeyPair keyPair, final String password) {
     // Resolve the key pair from persistent storage (could just be id)
        keyPair = this.asymetricKeyPairDAO.retrieveById(keyPair.getId());

        CryptoData privateKey = keyPair.getPrivateKey();
        if (privateKey instanceof PasswordedCryptoData == false) {
            throw new PhalanxException(PhalanxErrorCode.CP209,
                    "Key pair '%s' private key is not password protected", keyPair.getId());
        }
        PasswordedCryptoData passwordedCryptoData = (PasswordedCryptoData) privateKey;
        InternalSecretKeyToken secretKeyToken = this.passwordBasedCryptoService.decrypt(
                passwordedCryptoData, password, InternalSecretKeyToken.class);
        return symDecryptForPrivateKey(secretKeyToken, keyPair);
    }

    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public PrivateKeyToken decrypt(AsymmetricKeyPair keyPair, final PrivateKeyToken privateKeyToken) {
        // Resolve the key pair from persistent storage (could just be id)
        keyPair = this.asymetricKeyPairDAO.retrieveById(keyPair.getId());

        CryptoData privateKey = keyPair.getPrivateKey();
        if (privateKey instanceof AsymedCryptoData == false) {
            throw new PhalanxException(PhalanxErrorCode.CP210,
                    "Key pair '%s' private key is not protected by another private key", keyPair.getId());
        }
        AsymedCryptoData asymedCryptoData = (AsymedCryptoData) privateKey;
        InternalSecretKeyToken secretKeyToken = decrypt(
                asymedCryptoData, privateKeyToken, InternalSecretKeyToken.class);
        return symDecryptForPrivateKey(secretKeyToken, keyPair);
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public AsymmetricKeyPair generateKeyPair(AsymmetricKeyPair protectedWithPublicKeyFrom, final Principal owner) {
        // Resolve the key pair from persistent storage (could just be id)
        protectedWithPublicKeyFrom = this.asymetricKeyPairDAO.retrieveById(protectedWithPublicKeyFrom.getId());
        CryptoProfile defaultProfile = this.cryptoProfileService.retrieveDefault();
        KeyPair keyPair = this.phoenixAsymmetric.createKeyPair(defaultProfile);

        CryptoData publicKeyData = toCryptoData(keyPair.getPublicKey());
        InternalPrivateKeyToken internalPrivateKey = new InternalPrivateKeyToken(keyPair.getPrivateKey());
        InternalSecretKeyToken secretKeyToken = symEncryptPrivateKey(internalPrivateKey);

        AsymedCryptoData privateKeyData = encrypt(secretKeyToken, protectedWithPublicKeyFrom);
        AsymmetricKeyPair asymKeyPair = new AsymmetricKeyPair();
        asymKeyPair.setPrivateKey(privateKeyData);
        asymKeyPair.setPublicKey(publicKeyData);
        this.asymetricKeyPairDAO.create(asymKeyPair);

        return asymKeyPair;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public AsymmetricKeyPair generateKeyPair(final String passwordToProtectPrivateKey, final Principal owner) {
        CryptoProfile defaultProfile = this.cryptoProfileService.retrieveDefault();
        KeyPair keyPair = this.phoenixAsymmetric.createKeyPair(defaultProfile);

        CryptoData publicKeyData = toCryptoData(keyPair.getPublicKey());
        InternalPrivateKeyToken internalPrivateKey = new InternalPrivateKeyToken(keyPair.getPrivateKey());
        InternalSecretKeyToken secretKeyToken = symEncryptPrivateKey(internalPrivateKey);

        PasswordedCryptoData privateKeyData = this.passwordBasedCryptoService.encrypt(secretKeyToken, passwordToProtectPrivateKey);
        AsymmetricKeyPair asymKeyPair = new AsymmetricKeyPair();
        asymKeyPair.setPrivateKey(privateKeyData);
        asymKeyPair.setPublicKey(publicKeyData);
        this.asymetricKeyPairDAO.create(asymKeyPair);

        return asymKeyPair;
    }

    @Override
    public AsymmetricKeyPair assignKeyPair(final PrivateKeyToken privateKeyToken, Principal owner) {
        AsymmetricKeyPair keyPair = (AsymmetricKeyPair) privateKeyToken.getKeyPair();
        InternalPrivateKeyToken internalPrivateKeyToken = narrow(privateKeyToken);
        InternalSecretKeyToken secretKey = internalPrivateKeyToken.getSecretKey();

        AsymedCryptoData privateKeyData = null;
        if (owner != null) {
            owner = this.principalDAO.retrieveById(owner.getId());
            privateKeyData = encrypt(secretKey, owner.getDefaultKeyPair());
        }

        return prepareKeyPair(keyPair, privateKeyData);
    }


    /* (non-Javadoc)
     * @see org.brekka.phalanx.core.services.AsymmetricCryptoService#assignKeyPair(org.brekka.phalanx.api.model.PrivateKeyToken, org.brekka.phalanx.core.model.AsymmetricKeyPair)
     */
    @Override
    public AsymmetricKeyPair assignKeyPair(final PrivateKeyToken privateKeyToken, final AsymmetricKeyPair assignToKeyPair) {
        AsymmetricKeyPair keyPair = (AsymmetricKeyPair) privateKeyToken.getKeyPair();
        InternalPrivateKeyToken internalPrivateKeyToken = narrow(privateKeyToken);
        InternalSecretKeyToken secretKey = internalPrivateKeyToken.getSecretKey();
        AsymedCryptoData privateKeyData = encrypt(secretKey, assignToKeyPair);
        return prepareKeyPair(keyPair, privateKeyData);
    }

    /* (non-Javadoc)
     * @see org.brekka.phalanx.core.services.AsymmetricCryptoService#cloneKeyPairPublic(org.brekka.phalanx.core.model.AsymmetricKeyPair)
     */
    @Override
    public AsymmetricKeyPair cloneKeyPairPublic(final AsymmetricKeyPair keyPair) {
        AsymmetricKeyPair asymKeyPair = new AsymmetricKeyPair();
        asymKeyPair.setPublicKey(keyPair.getPublicKey());
        this.asymetricKeyPairDAO.create(asymKeyPair);
        return asymKeyPair;
    }


    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public AsymmetricKeyPair retrieveKeyPair(final UUID keyPairId) {
        return this.asymetricKeyPairDAO.retrieveById(keyPairId);
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void deleteKeyPair(final UUID keyPairId) {
        this.asymetricKeyPairDAO.delete(keyPairId);
    }

    /* (non-Javadoc)
     * @see org.brekka.phalanx.core.services.AsymmetricCryptoService#sign(org.w3c.dom.Document, org.brekka.phalanx.api.model.PrivateKeyToken)
     */
    @Override
    public Document sign(final Document document, final PrivateKeyToken privateKeyToken) {
        InternalPrivateKeyToken internalPrivateKeyToken = narrow(privateKeyToken);
        final PrivateKey privateKey = internalPrivateKeyToken.getPrivateKey();
        final AsymmetricKeyPair keyPair = retrieveKeyPair(privateKeyToken.getKeyPair().getId());
        return this.phoenixAsymmetric.sign(document, new KeyPair() {
            @Override
            public PublicKey getPublicKey() {
                return toPublicKey(keyPair.getPublicKey());
            }
            @Override
            public PrivateKey getPrivateKey() {
                return privateKey;
            }
        });
    }

    protected PublicKey toPublicKey(final CryptoData publicKeyData) {
        if (publicKeyData.getClass() != CryptoData.class) {
            throw new PhalanxException(PhalanxErrorCode.CP201,
                    "CryptoData item '%s' is not plain", publicKeyData.getId());
        }
        byte[] data = publicKeyData.getData();
        PublicKey publicKey = this.phoenixAsymmetric.toPublicKey(data, profileOf(publicKeyData));
        return publicKey;
    }

    /**
     * @param publicKeyData
     * @return
     */
    private CryptoProfile profileOf(final CryptoData data) {
        return this.cryptoProfileService.retrieveProfile(data.getProfile());
    }

    protected CryptoData toCryptoData(final Key key) {
        CryptoData publicKeyData = new CryptoData();
        publicKeyData.setData(key.getEncoded());
        publicKeyData.setProfile(key.getCryptoProfile().getNumber());
        this.cryptoDataDAO.create(publicKeyData);
        return publicKeyData;
    }

    protected SymedCryptoData narrow(final CryptoData cryptoData) {
        if (cryptoData instanceof SymedCryptoData == false) {
            throw new PhalanxException(PhalanxErrorCode.CP212,
                    "The CryptoData used to store the private key is not a SymCryptoData, it is instead '%s'",
                    cryptoData.getClass().getName());
        }
        SymedCryptoData symedCryptoData = (SymedCryptoData) cryptoData;
        return symedCryptoData;
    }


    protected PrivateKeyToken symDecryptForPrivateKey(final InternalSecretKeyToken secretKeyToken, final AsymmetricKeyPair keyPair) {
        UUID symDataId = secretKeyToken.getSymedCryptoData().getId();
        CryptoData cryptoData = this.cryptoDataDAO.retrieveById(symDataId);
        SymedCryptoData symedCryptoData = narrow(cryptoData);
        InternalPrivateKeyToken privateKeyToken = this.symmetricCryptoService.decrypt(symedCryptoData, secretKeyToken, InternalPrivateKeyToken.class);
        privateKeyToken.setSecretKey(secretKeyToken);
        privateKeyToken.setAsymetricKeyPair(keyPair);
        return privateKeyToken;
    }

    protected InternalSecretKeyToken symEncryptPrivateKey(final InternalPrivateKeyToken internalPrivateKey) {
        InternalSecretKeyToken secretKeyToken = (InternalSecretKeyToken) this.symmetricCryptoService.generateSecretKey();
        SymedCryptoData symedCryptoData = this.symmetricCryptoService.encrypt(internalPrivateKey, secretKeyToken);
        secretKeyToken.setSymedCryptoData(symedCryptoData);
        internalPrivateKey.setSecretKey(secretKeyToken);
        return secretKeyToken;
    }

    /**
     * @param owner
     * @param keyPair
     * @param privateKeyData
     * @return
     */
    protected AsymmetricKeyPair prepareKeyPair(final AsymmetricKeyPair keyPair, final AsymedCryptoData privateKeyData) {
        AsymmetricKeyPair asymKeyPair = new AsymmetricKeyPair();
        asymKeyPair.setPrivateKey(privateKeyData);
        // Keep the public key the same
        asymKeyPair.setPublicKey(keyPair.getPublicKey());
        this.asymetricKeyPairDAO.create(asymKeyPair);
        return asymKeyPair;
    }

    private static InternalPrivateKeyToken narrow(final PrivateKeyToken privateKeyToken) {
        if (privateKeyToken instanceof InternalPrivateKeyToken == false) {
            throw new PhalanxException(PhalanxErrorCode.CP203,
                    "Private key token must be an instance issued previously by this service. Found '%s'.",
                    privateKeyToken.getClass().getSimpleName());
        }
        return (InternalPrivateKeyToken) privateKeyToken;
    }


    public void setAsymetricKeyPairDAO(final AsymmetricKeyPairDAO asymetricKeyPairDAO) {
        this.asymetricKeyPairDAO = asymetricKeyPairDAO;
    }

    public void setCryptoDataDAO(final CryptoDataDAO cryptoDataDAO) {
        this.cryptoDataDAO = cryptoDataDAO;
    }

    public void setPasswordBasedCryptoService(final PasswordBasedCryptoService passwordBasedCryptoService) {
        this.passwordBasedCryptoService = passwordBasedCryptoService;
    }

    public void setSymmetricCryptoService(final SymmetricCryptoService symmetricCryptoService) {
        this.symmetricCryptoService = symmetricCryptoService;
    }
}
