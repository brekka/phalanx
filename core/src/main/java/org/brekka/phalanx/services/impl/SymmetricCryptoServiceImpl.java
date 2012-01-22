package org.brekka.phalanx.services.impl;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.brekka.phalanx.PhalanxErrorCode;
import org.brekka.phalanx.PhalanxException;
import org.brekka.phalanx.crypto.CryptoFactory;
import org.brekka.phalanx.dao.CryptoDataDAO;
import org.brekka.phalanx.model.SecretKeyToken;
import org.brekka.phalanx.model.SymedCryptoData;
import org.brekka.phalanx.services.SymmetricCryptoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class SymmetricCryptoServiceImpl extends AbstractCryptoService implements SymmetricCryptoService {

    @Autowired
    private CryptoDataDAO cryptoDataDAO;
    
    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public <T> T decrypt(SymedCryptoData cryptoData, SecretKeyToken secretKeyToken, Class<T> expectedType) {
        CryptoFactory profile = getCryptoProfileRegistry().getFactory(cryptoData.getProfile());
        CryptoFactory.Symmetric symmetricProfile = profile.getSymmetric();
        InternalSecretKeyToken internalSecretKeyToken = verify(secretKeyToken);
        SecretKey secretKey = internalSecretKeyToken.getSecretKey();
        IvParameterSpec initializationVector = new IvParameterSpec(cryptoData.getIv());
        
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, secretKey, initializationVector, symmetricProfile);
        byte[] data;
        try {
            data = cipher.doFinal(cryptoData.getData());
        } catch (GeneralSecurityException e) {
            throw new PhalanxException(PhalanxErrorCode.CP106, e, 
                    "Failed to decrypt CryptoData with id '%s'", cryptoData.getId());
        }
        return toType(data, expectedType, cryptoData.getId(), profile);
    }


    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public SymedCryptoData encrypt(Object obj, SecretKeyToken secretKeyToken) {
        CryptoFactory profile = getCryptoProfileRegistry().getDefault();
        CryptoFactory.Symmetric symmetricProfile = profile.getSymmetric();
        InternalSecretKeyToken internalSecretKeyToken = verify(secretKeyToken);
        SecretKey secretKey = internalSecretKeyToken.getSecretKey();
        IvParameterSpec initializationVector = generateInitializationVector(profile);
        byte[] data = toBytes(obj);
        
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, secretKey, initializationVector, symmetricProfile);
        byte[] cipherData;
        try {
            cipherData = cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new PhalanxException(PhalanxErrorCode.CP105, e, 
                    "Failed to symmetric encrypt object");
        }
        
        SymedCryptoData cryptoData = new SymedCryptoData();
        cryptoData.setIv(initializationVector.getIV());
        cryptoData.setData(cipherData);
        cryptoData.setProfile(profile.getProfileId());
        cryptoDataDAO.create(cryptoData);
        return cryptoData;
    }
    
    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public SecretKeyToken generateSecretKey() {
        CryptoFactory profile = getCryptoProfileRegistry().getDefault();
        KeyGenerator keyGenerator = profile.getSymmetric().getKeyGenerator();
        SecretKey generateKey = keyGenerator.generateKey();
        return new InternalSecretKeyToken(generateKey);
    }
    
    
    protected InternalSecretKeyToken verify(SecretKeyToken secretKey) {
        if (secretKey == null) {
            throw new NullPointerException("No secret key token supplied");
        }
        if (secretKey instanceof InternalSecretKeyToken == false) {
            throw new PhalanxException(PhalanxErrorCode.CP104, 
                    "Secret key token must be an instance issued previously by this service. Found '%s'.", 
                    secretKey.getClass().getSimpleName());
        }
        return (InternalSecretKeyToken) secretKey;
    }
    
    protected IvParameterSpec generateInitializationVector(CryptoFactory profile) {
        byte[] ivBytes = new byte[profile.getSymmetric().getIvLength()];
        profile.getSecureRandom().nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        return iv;
    }
    
    protected Cipher getCipher(int mode, Key key, AlgorithmParameterSpec parameter, CryptoFactory.Symmetric symmetricProfile) {
        Cipher cipher = symmetricProfile.getInstance();
        try {
            cipher.init(mode, key, parameter);
        } catch (GeneralSecurityException e) {
            throw new PhalanxException(PhalanxErrorCode.CP102, e, 
                    "Problem initializing symmetric cipher");
        }
        return cipher;
    }
    
    
    public void setCryptoDataDAO(CryptoDataDAO cryptoDataDAO) {
        this.cryptoDataDAO = cryptoDataDAO;
    }
    
}
