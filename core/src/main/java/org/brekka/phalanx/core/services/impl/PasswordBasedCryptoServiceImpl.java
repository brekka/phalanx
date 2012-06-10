package org.brekka.phalanx.core.services.impl;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.lang3.ArrayUtils;
import org.brekka.phalanx.api.PhalanxErrorCode;
import org.brekka.phalanx.api.PhalanxException;
import org.brekka.phalanx.core.dao.CryptoDataDAO;
import org.brekka.phalanx.core.model.PasswordedCryptoData;
import org.brekka.phalanx.core.services.PasswordBasedCryptoService;
import org.brekka.phoenix.CryptoFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class PasswordBasedCryptoServiceImpl extends AbstractCryptoService implements PasswordBasedCryptoService {

    @Autowired
    private CryptoDataDAO cryptoDataDAO;
    
    @Override
    @Transactional(propagation=Propagation.SUPPORTS, noRollbackFor={ PhalanxException.class })
    public <T> T decrypt(PasswordedCryptoData cryptoData, String password, Class<T> expectedType) {
        cryptoData = (PasswordedCryptoData) cryptoDataDAO.retrieveById(cryptoData.getId());
        
        byte[] data = cryptoData.getData();
        byte[] salt = cryptoData.getSalt();
        
        CryptoFactory profile = getCryptoProfileRegistry().getFactory(cryptoData.getProfile());
        
        byte[] result = crypt(Cipher.DECRYPT_MODE, data, salt, password.toCharArray(), profile.getPasswordBased());
        
        MessageDigest digestInstance = profile.getDigestInstance();
        // Generate a digest for the data
        int actualDataLength = result.length - digestInstance.getDigestLength();
        digestInstance.update(result, digestInstance.getDigestLength(), actualDataLength);
        byte[] digest = digestInstance.digest();
        for (int i = 0; i < digest.length; i++) {
            if (digest[i] != result[i]) {
                throw new PhalanxException(PhalanxErrorCode.CP302, 
                        "The password is incorrect");
            }
        }
        result = ArrayUtils.subarray(result, digestInstance.getDigestLength(), result.length);
        return toType(result, expectedType, cryptoData.getId(), profile);
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public PasswordedCryptoData encrypt(Object obj, String password) {
        CryptoFactory profile = getCryptoProfileRegistry().getDefault();
        CryptoFactory.PasswordBased passwordBasedProfile = profile.getPasswordBased();
        
        byte[] data = toBytes(obj);
        
        MessageDigest digestInstance = profile.getDigestInstance();
        byte[] digest = digestInstance.digest(data);
        
        byte[] salt = new byte[passwordBasedProfile.getSaltLength()];
        profile.getSecureRandom().nextBytes(salt);
        
        ByteBuffer dataBuffer = ByteBuffer.allocate(data.length + digest.length);
        dataBuffer.put(digest);
        dataBuffer.put(data);

        byte[] result = crypt(Cipher.ENCRYPT_MODE, dataBuffer.array(), salt, password.toCharArray(), passwordBasedProfile);
        
        PasswordedCryptoData encryptedData = new PasswordedCryptoData();
        encryptedData.setData(result);
        encryptedData.setSalt(salt);
        encryptedData.setProfile(profile.getProfileId());
        cryptoDataDAO.create(encryptedData);
        return encryptedData;
    }
    

    protected byte[] crypt(int mode, byte[] data, byte[] salt, char[] password, CryptoFactory.PasswordBased passwordBasedProfile) {
        int iterationCount = calculateIterations(password.length, passwordBasedProfile.getIterationFactor());
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount);

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        
        Cipher encryptionCipher = passwordBasedProfile.getInstance();
        try {
            SecretKeyFactory secretKeyFactory = passwordBasedProfile.getSecretKeyFactory();
            SecretKey pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);
            encryptionCipher.init(mode, pbeKey, pbeParamSpec);
            return encryptionCipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new PhalanxException(PhalanxErrorCode.CP300, e, 
                    "Failed to perform encryption/decryption operation");
        }
    }
    
    public void setCryptoDataDAO(CryptoDataDAO cryptoDataDAO) {
        this.cryptoDataDAO = cryptoDataDAO;
    }
    
    private static int calculateIterations(int length, int iterationFactor) {
        return ((length * 2) + 13) * iterationFactor;
    }

}
