package org.brekka.phalanx.services.impl;

import java.util.UUID;

import org.brekka.phalanx.PhalanxErrorCode;
import org.brekka.phalanx.PhalanxException;
import org.brekka.phalanx.dao.CryptoDataDAO;
import org.brekka.phalanx.model.AsymedCryptoData;
import org.brekka.phalanx.model.AsymmetricKeyPair;
import org.brekka.phalanx.model.AuthenticatedPrincipal;
import org.brekka.phalanx.model.CryptoData;
import org.brekka.phalanx.model.PasswordedCryptoData;
import org.brekka.phalanx.model.Principal;
import org.brekka.phalanx.model.PrivateKeyToken;
import org.brekka.phalanx.services.AsymmetricCryptoService;
import org.brekka.phalanx.services.PasswordBasedCryptoService;
import org.brekka.phalanx.services.PhalanxService;
import org.brekka.phalanx.services.PrincipalService;
import org.brekka.phalanx.services.SymmetricCryptoService;
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
    private SymmetricCryptoService symmetricCryptoService;
    
    @Autowired
    private AsymmetricCryptoService asymmetricCryptoService;
    
    @Autowired
    private PrincipalService principalService;
    
    @Autowired
    private CryptoDataDAO cryptoDataDAO;
    
    
    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public UUID asyncEncrypt(byte[] data, UUID keyPairId) {
        AsymmetricKeyPair keyPair = asymmetricCryptoService.retrieveKeyPair(keyPairId);
        AsymedCryptoData asymedCryptoData = asymmetricCryptoService.encrypt(data, keyPair);
        return asymedCryptoData.getId();
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public byte[] asyncDecrypt(UUID asymedCryptoDataId, PrivateKeyToken privateKeyToken) {
        AsymedCryptoData dataItem = retrieveDataItem(asymedCryptoDataId, AsymedCryptoData.class);
        byte[] data = asymmetricCryptoService.decrypt(dataItem, privateKeyToken, byte[].class);
        return data;
    }



    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public UUID pbeEncrypt(byte[] data, String password) {
        PasswordedCryptoData cryptoData = passwordBasedCryptoService.encrypt(data, password);
        return cryptoData.getId();
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public byte[] pbeDecrypt(UUID passwordedCryptoDataId, String password) {
        PasswordedCryptoData dataItem = retrieveDataItem(passwordedCryptoDataId, PasswordedCryptoData.class);
        byte[] data = passwordBasedCryptoService.decrypt(dataItem, password, byte[].class);
        return data;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public PrivateKeyToken asyncDecryptKeyPair(UUID asymmetricKeyPairId, PrivateKeyToken privateKeyToken) {
        AsymmetricKeyPair keyPair = asymmetricCryptoService.retrieveKeyPair(asymmetricKeyPairId);
        PrivateKeyToken nextPrivateKeyToken = asymmetricCryptoService.decrypt(keyPair, privateKeyToken);
        return nextPrivateKeyToken;
    }
    
    

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public UUID generateKeyPair(UUID protectedByKeyPairId, UUID ownerPrincipalId) {
        AsymmetricKeyPair keyPair = asymmetricCryptoService.retrieveKeyPair(protectedByKeyPairId);
        Principal principal = principalService.retrieveById(ownerPrincipalId);
        AsymmetricKeyPair newKeyPair = asymmetricCryptoService.generateKeyPair(keyPair, principal);
        return newKeyPair.getId();
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public UUID assignKeyPair(PrivateKeyToken privateKeyToken, UUID assignToPrincipalId) {
        Principal assignToPrincipal = principalService.retrieveById(assignToPrincipalId);
        AsymmetricKeyPair newKeyPair = asymmetricCryptoService.assignKeyPair(privateKeyToken, assignToPrincipal);
        return newKeyPair.getId();
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void deleteCryptoDataItem(UUID cryptoDataItemId) {
        cryptoDataDAO.delete(cryptoDataItemId);
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void deleteKeyPair(UUID keyPairId) {
        asymmetricCryptoService.deleteKeyPair(keyPairId);
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public UUID createPrincipal(String password) {
        Principal principal = principalService.createPrincipal(password);
        return principal.getId();
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void deletePrincipal(UUID principalId) {
        principalService.deletePrincipal(principalId);
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public AuthenticatedPrincipal authenticate(UUID principalId, String password) {
        Principal principal = principalService.retrieveById(principalId);
        AuthenticatedPrincipal authenticatedPrincipal = principalService.authenticate(principal, password);
        return authenticatedPrincipal;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void changePassword(UUID principalId, String currentPassword, String newPassword) {
        Principal principal = principalService.retrieveById(principalId);
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
    protected <T extends CryptoData> T retrieveDataItem(UUID cryptoDataId, Class<T> expectedType) {
        CryptoData cryptoData = cryptoDataDAO.retrieveById(cryptoDataId);
        if (!expectedType.isAssignableFrom(cryptoData.getClass())) {
            throw new PhalanxException(PhalanxErrorCode.CP600, "Expected crypto data type %s, found %s", 
                    expectedType.getSimpleName(), cryptoData.getClass().getSimpleName());
        }
        return (T) cryptoData;
    }

    
}
