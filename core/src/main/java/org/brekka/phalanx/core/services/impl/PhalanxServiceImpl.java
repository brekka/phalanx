package org.brekka.phalanx.core.services.impl;

import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.api.model.CryptedData;
import org.brekka.phalanx.api.model.KeyPair;
import org.brekka.phalanx.api.model.PrivateKeyToken;
import org.brekka.phalanx.api.services.PhalanxService;
import org.brekka.phalanx.core.PhalanxErrorCode;
import org.brekka.phalanx.core.PhalanxException;
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
    public CryptedData asymEncrypt(byte[] data, KeyPair keyPair) {
        AsymmetricKeyPair asymKeyPair = asymmetricCryptoService.retrieveKeyPair(keyPair.getId());
        AsymedCryptoData asymedCryptoData = asymmetricCryptoService.encrypt(data, asymKeyPair);
        return asymedCryptoData;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public byte[] asymDecrypt(CryptedData asymedCryptoDataId, PrivateKeyToken privateKeyToken) {
        AsymedCryptoData dataItem = retrieveDataItem(asymedCryptoDataId, AsymedCryptoData.class);
        byte[] data = asymmetricCryptoService.decrypt(dataItem, privateKeyToken, byte[].class);
        return data;
    }



    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public CryptedData pbeEncrypt(byte[] data, String password) {
        PasswordedCryptoData cryptoData = passwordBasedCryptoService.encrypt(data, password);
        return cryptoData;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public byte[] pbeDecrypt(CryptedData passwordedCryptoData, String password) {
        PasswordedCryptoData dataItem = retrieveDataItem(passwordedCryptoData, PasswordedCryptoData.class);
        byte[] data = passwordBasedCryptoService.decrypt(dataItem, password, byte[].class);
        return data;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public PrivateKeyToken decryptKeyPair(KeyPair keyPairIn, PrivateKeyToken privateKeyToken) {
        AsymmetricKeyPair keyPair = asymmetricCryptoService.retrieveKeyPair(keyPairIn.getId());
        PrivateKeyToken nextPrivateKeyToken = asymmetricCryptoService.decrypt(keyPair, privateKeyToken);
        return nextPrivateKeyToken;
    }
    
    

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public KeyPair generateKeyPair(KeyPair protectedByKeyPair, org.brekka.phalanx.api.model.Principal ownerPrincipal) {
        AsymmetricKeyPair keyPair = asymmetricCryptoService.retrieveKeyPair(protectedByKeyPair.getId());
        Principal principal = principalService.retrieveById(ownerPrincipal.getId());
        AsymmetricKeyPair newKeyPair = asymmetricCryptoService.generateKeyPair(keyPair, principal);
        return newKeyPair;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public KeyPair assignKeyPair(PrivateKeyToken privateKeyToken, org.brekka.phalanx.api.model.Principal assignToPrincipalIn) {
        Principal assignToPrincipal = principalService.retrieveById(assignToPrincipalIn.getId());
        AsymmetricKeyPair newKeyPair = asymmetricCryptoService.assignKeyPair(privateKeyToken, assignToPrincipal);
        return newKeyPair;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void deleteCryptedData(CryptedData cryptoDataItem) {
        cryptoDataDAO.delete(cryptoDataItem.getId());
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void deleteKeyPair(KeyPair keyPair) {
        asymmetricCryptoService.deleteKeyPair(keyPair.getId());
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public org.brekka.phalanx.api.model.Principal createPrincipal(String password) {
        Principal principal = principalService.createPrincipal(password);
        return principal;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void deletePrincipal(org.brekka.phalanx.api.model.Principal principal) {
        principalService.deletePrincipal(principal.getId());
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public AuthenticatedPrincipal authenticate(org.brekka.phalanx.api.model.Principal principal, String password) {
        Principal corePrincipal = principalService.retrieveById(principal.getId());
        AuthenticatedPrincipal authenticatedPrincipal = principalService.authenticate(corePrincipal, password);
        return authenticatedPrincipal;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void changePassword(org.brekka.phalanx.api.model.Principal principalIn, String currentPassword, String newPassword) {
        Principal principal = principalService.retrieveById(principalIn.getId());
        AsymmetricKeyPair keyPair = principal.getDefaultKeyPair();
        CryptoData privateKey = keyPair.getPrivateKey();
        if (privateKey instanceof PasswordedCryptoData == false) {
            throw new PhalanxException(PhalanxErrorCode.CP209, 
                    "Key pair '%s' private key is not password protected", keyPair.getId());
        }
        PasswordedCryptoData passwordedCryptoData = (PasswordedCryptoData) privateKey;
        InternalSecretKeyToken secretKeyToken = passwordBasedCryptoService.decrypt(
                passwordedCryptoData, currentPassword, InternalSecretKeyToken.class);
        
        PasswordedCryptoData privateKeyData = passwordBasedCryptoService.encrypt(secretKeyToken, newPassword);
        
        asymmetricCryptoService.replacePrivateKey(keyPair, privateKeyData);
    }
    
    @SuppressWarnings("unchecked")
    protected <T extends CryptoData> T retrieveDataItem(CryptedData cryptedData, Class<T> expectedType) {
        CryptoData cryptoData = cryptoDataDAO.retrieveById(cryptedData.getId());
        if (!expectedType.isAssignableFrom(cryptoData.getClass())) {
            throw new PhalanxException(PhalanxErrorCode.CP600, "Expected crypto data type %s, found %s", 
                    expectedType.getSimpleName(), cryptoData.getClass().getSimpleName());
        }
        return (T) cryptoData;
    }

    
}
