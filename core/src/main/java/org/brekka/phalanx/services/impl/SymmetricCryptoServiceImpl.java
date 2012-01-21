package org.brekka.phalanx.services.impl;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.brekka.phalanx.CryptoErrorCode;
import org.brekka.phalanx.CryptoException;
import org.brekka.phalanx.dao.CryptoDataDAO;
import org.brekka.phalanx.model.SecretKeyToken;
import org.brekka.phalanx.model.SymedCryptoData;
import org.brekka.phalanx.model.SymmetricInfo;
import org.brekka.phalanx.profile.CryptoProfile;
import org.brekka.phalanx.services.SymmetricCryptoService;
import org.brekka.phalanx.services.SymmetricEncryptor;
import org.brekka.xml.v1.phalanx.SymmetricInfoType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service("resourceCryptoService")
@Transactional
public class SymmetricCryptoServiceImpl extends AbstractCryptoService implements SymmetricCryptoService {

    @Autowired
    private CryptoDataDAO cryptoDataDAO;
    
    @Override
    public SymmetricEncryptor encryptor() {
        return new SymmetricEncryptorImpl();
    }
    
    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public <T> T decrypt(SymedCryptoData cryptoData, SecretKeyToken secretKeyToken, Class<T> expectedType) {
        CryptoProfile profile = getCryptoProfileRegistry().getProfile(cryptoData.getProfile());
        CryptoProfile.Symmetric symmetricProfile = profile.getSymmetric();
        InternalSecretKeyToken internalSecretKeyToken = verify(secretKeyToken);
        SecretKey secretKey = internalSecretKeyToken.getSecretKey();
        IvParameterSpec initializationVector = new IvParameterSpec(cryptoData.getIv());
        
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, secretKey, initializationVector, symmetricProfile);
        byte[] data;
        try {
            data = cipher.doFinal(cryptoData.getData());
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.CP106, e, 
                    "Failed to decrypt CryptoData with id '%s'", cryptoData.getId());
        }
        return toType(data, expectedType, cryptoData.getId(), profile);
    }


    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public SymedCryptoData encrypt(Object obj, SecretKeyToken secretKeyToken) {
        CryptoProfile profile = getCryptoProfileRegistry().getDefaultProfile();
        CryptoProfile.Symmetric symmetricProfile = profile.getSymmetric();
        InternalSecretKeyToken internalSecretKeyToken = verify(secretKeyToken);
        SecretKey secretKey = internalSecretKeyToken.getSecretKey();
        IvParameterSpec initializationVector = generateInitializationVector(profile);
        byte[] data = toBytes(obj);
        
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, secretKey, initializationVector, symmetricProfile);
        byte[] cipherData;
        try {
            cipherData = cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.CP105, e, 
                    "Failed to symmetric encrypt object");
        }
        
        SymedCryptoData cryptoData = new SymedCryptoData();
        cryptoData.setIv(initializationVector.getIV());
        cryptoData.setData(cipherData);
        cryptoDataDAO.create(cryptoData);
        return cryptoData;
    }
    
    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public SecretKeyToken generateSecretKey() {
        CryptoProfile profile = getCryptoProfileRegistry().getDefaultProfile();
        KeyGenerator keyGenerator = profile.getSymmetric().getKeyGenerator();
        SecretKey generateKey = keyGenerator.generateKey();
        return new InternalSecretKeyToken(generateKey);
    }
    
    
    protected InternalSecretKeyToken verify(SecretKeyToken secretKey) {
        if (secretKey == null) {
            throw new NullPointerException("No secret key token supplied");
        }
        if (secretKey instanceof InternalSecretKeyToken == false) {
            throw new CryptoException(CryptoErrorCode.CP104, 
                    "Secret key token must be an instance issued previously by this service. Found '%s'.", 
                    secretKey.getClass().getSimpleName());
        }
        return (InternalSecretKeyToken) secretKey;
    }
    
    protected IvParameterSpec generateInitializationVector(CryptoProfile profile) {
        byte[] ivBytes = new byte[profile.getSymmetric().getIvLength()];
        profile.getSecureRandom().nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        return iv;
    }
    
    protected Cipher getCipher(int mode, Key key, AlgorithmParameterSpec parameter, CryptoProfile.Symmetric symmetricProfile) {
        Cipher cipher = symmetricProfile.getInstance();
        try {
            cipher.init(mode, key, parameter);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.CP102, e, 
                    "Problem initializing symmetric cipher");
        }
        return cipher;
    }
    
    
    public void setCryptoDataDAO(CryptoDataDAO cryptoDataDAO) {
        this.cryptoDataDAO = cryptoDataDAO;
    }
    
    
    private class SymmetricEncryptorImpl implements SymmetricEncryptor {
        
        private final int profileId;
        private final SecretKey secretKey;
        private final IvParameterSpec initializationVector;
        private final Cipher cipher;
        
        public SymmetricEncryptorImpl() {
            CryptoProfile profile = getCryptoProfileRegistry().getDefaultProfile();
            CryptoProfile.Symmetric synchronousProfile = profile.getSymmetric();
            this.secretKey = synchronousProfile.getKeyGenerator().generateKey();
            this.initializationVector = generateInitializationVector(profile);
            this.cipher = getCipher(Cipher.ENCRYPT_MODE, secretKey, initializationVector, synchronousProfile);
            this.profileId = profile.getId();
        }
        
        /**
         * - Count
         * - Digest
         * - GZIP
         * - Encrypt
         */
        @Override
        public OutputStream encrypt(OutputStream os) {
            CipherOutputStream cos = new CipherOutputStream(os, cipher);
            GZIPOutputStream zos;
            try {
                zos = new GZIPOutputStream(cos);
            } catch (IOException e) {
                throw new CryptoException(CryptoErrorCode.CP700, e, 
                        "Failed to create GZIP instance for encryption stream");
            }
            return zos;
        }
        
        @Override
        public SymmetricInfo complete() {
            SymmetricInfoType symType = SymmetricInfoType.Factory.newInstance();
            symType.setProfile(profileId);
            symType.setIV(initializationVector.getIV());
            symType.setKey(secretKey.getEncoded());
            return new InternalSymmetricInfo(symType);
        }
    }
}
