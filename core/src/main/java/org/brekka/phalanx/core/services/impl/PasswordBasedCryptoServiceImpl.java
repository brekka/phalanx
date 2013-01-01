package org.brekka.phalanx.core.services.impl;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.crypto.BadPaddingException;

import org.apache.commons.lang3.ArrayUtils;
import org.brekka.phalanx.api.PhalanxErrorCode;
import org.brekka.phalanx.api.PhalanxException;
import org.brekka.phalanx.core.dao.CryptoDataDAO;
import org.brekka.phalanx.core.model.PasswordedCryptoData;
import org.brekka.phalanx.core.services.PasswordBasedCryptoService;
import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.CryptoResult;
import org.brekka.phoenix.api.DerivedKey;
import org.brekka.phoenix.api.DigestResult;
import org.brekka.phoenix.api.SymmetricCryptoSpec;
import org.brekka.phoenix.api.services.DerivedKeyCryptoService;
import org.brekka.phoenix.api.services.DigestCryptoService;
import org.brekka.phoenix.core.PhoenixException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class PasswordBasedCryptoServiceImpl extends AbstractCryptoService implements PasswordBasedCryptoService {

    @Autowired
    private CryptoDataDAO cryptoDataDAO;
    
    @Autowired
    protected DerivedKeyCryptoService phoenixDerived;
    
    @Autowired
    protected DigestCryptoService phoenixDigest;

    
    @Override
    @Transactional(propagation=Propagation.SUPPORTS, noRollbackFor={ PhalanxException.class })
    public <T> T decrypt(PasswordedCryptoData cryptoData, String password, Class<T> expectedType) {
        cryptoData = (PasswordedCryptoData) cryptoDataDAO.retrieveById(cryptoData.getId());
        
        byte[] cipherText = cryptoData.getData();
        byte[] salt = cryptoData.getSalt();
        Integer iterations = cryptoData.getIterations();
        byte[] key = toKey(password);
        
        CryptoProfile cryptoProfile = cryptoProfileService.retrieveProfile(cryptoData.getProfile());
        DerivedKey derivedKey = phoenixDerived.apply(key, salt, iterations, cryptoProfile);
        SymmetricCryptoSpec symmetricCryptoSpec = phoenixSymmetric.toSymmetricCryptoSpec(derivedKey);
        
        byte[] result;
        try {
            result = phoenixSymmetric.decrypt(cipherText, symmetricCryptoSpec);
        } catch (PhoenixException e) {
            if (e.getCause() instanceof BadPaddingException) {
                throw new PhalanxException(PhalanxErrorCode.CP302, 
                        "The password is incorrect");
            }
            throw e;
        }
        int digestLength = phoenixDigest.getDigestLength(cryptoProfile);
        
        byte[] digest = ArrayUtils.subarray(result, 0, digestLength);
        byte[] data = ArrayUtils.subarray(result, digestLength, result.length);
        DigestResult digestResult = phoenixDigest.digest(data, cryptoProfile);
        
        if (!Arrays.equals(digest, digestResult.getDigest())) {
            throw new PhalanxException(PhalanxErrorCode.CP302, 
                    "The password is incorrect");
        }
        return toType(data, expectedType, cryptoData.getId(), cryptoProfile);
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public PasswordedCryptoData encrypt(Object obj, String password) {
        CryptoProfile cryptoProfile = cryptoProfileService.retrieveDefault();
        byte[] data = toBytes(obj);
        
        DigestResult digestResult = phoenixDigest.digest(data, cryptoProfile);
        byte[] digest = digestResult.getDigest();
        
        ByteBuffer dataBuffer = ByteBuffer.allocate(data.length + digest.length);
        dataBuffer.put(digest);
        dataBuffer.put(data);
        data = dataBuffer.array();
        
        byte[] key = toKey(password);
        
        DerivedKey derivedKey = phoenixDerived.apply(key, cryptoProfile);
        SymmetricCryptoSpec symmetricCryptoSpec = phoenixSymmetric.toSymmetricCryptoSpec(derivedKey);
        
        CryptoResult<SymmetricCryptoSpec> cryptoResult = phoenixSymmetric.encrypt(data, symmetricCryptoSpec);
        
        PasswordedCryptoData encryptedData = new PasswordedCryptoData();
        encryptedData.setData(cryptoResult.getCipherText());
        encryptedData.setSalt(derivedKey.getSalt());
        encryptedData.setProfile(cryptoProfile.getNumber());
        cryptoDataDAO.create(encryptedData);
        return encryptedData;
    }
    
    protected byte[] toKey(String password) {
        try {
            return password.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
    
    public void setCryptoDataDAO(CryptoDataDAO cryptoDataDAO) {
        this.cryptoDataDAO = cryptoDataDAO;
    }
    
    /**
     * @param phoenixDerived the phoenixDerived to set
     */
    public void setPhoenixDerived(DerivedKeyCryptoService phoenixDerived) {
        this.phoenixDerived = phoenixDerived;
    }
    
    /**
     * @param phoenixDigest the phoenixDigest to set
     */
    public void setPhoenixDigest(DigestCryptoService phoenixDigest) {
        this.phoenixDigest = phoenixDigest;
    }
}
