package org.brekka.phalanx.services.impl;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.brekka.phalanx.CryptoErrorCode;
import org.brekka.phalanx.CryptoException;
import org.brekka.phalanx.dao.CryptoDataDAO;
import org.brekka.phalanx.model.PasswordedCryptoData;
import org.brekka.phalanx.profile.CryptoProfile;
import org.brekka.phalanx.services.PasswordBasedCryptoService;
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
    @Transactional(propagation=Propagation.SUPPORTS)
    public <T> T decrypt(PasswordedCryptoData cryptoData, String password, Class<T> expectedType) {
        byte[] data = cryptoData.getData();
        byte[] salt = cryptoData.getSalt();
        
        CryptoProfile profile = getCryptoProfileRegistry().getProfile(cryptoData.getProfile());
        
        byte[] result = crypt(Cipher.DECRYPT_MODE, data, salt, password.toCharArray(), profile.getPasswordBased());
        
        return toType(result, expectedType, cryptoData.getId(), profile);
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public PasswordedCryptoData encrypt(Object obj, String password) {
        CryptoProfile profile = getCryptoProfileRegistry().getDefaultProfile();
        CryptoProfile.PasswordBased passwordBasedProfile = profile.getPasswordBased();
        
        byte[] data = toBytes(obj);
        
        byte[] salt = new byte[passwordBasedProfile.getSaltLength()];
        profile.getSecureRandom().nextBytes(salt);

        byte[] result = crypt(Cipher.ENCRYPT_MODE, data, salt, password.toCharArray(), passwordBasedProfile);
        
        PasswordedCryptoData encryptedData = new PasswordedCryptoData();
        encryptedData.setData(result);
        encryptedData.setSalt(salt);
        cryptoDataDAO.create(encryptedData);
        return encryptedData;
    }
    
    protected byte[] crypt(int mode, byte[] data, byte[] salt, char[] password, CryptoProfile.PasswordBased passwordBasedProfile) {
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
            throw new CryptoException(CryptoErrorCode.CP300, e, 
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
