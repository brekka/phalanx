package org.brekka.phalanx.core.services.impl;

import org.brekka.phalanx.api.PhalanxErrorCode;
import org.brekka.phalanx.api.PhalanxException;
import org.brekka.phalanx.core.dao.CryptoDataDAO;
import org.brekka.phalanx.core.model.SecretKeyToken;
import org.brekka.phalanx.core.model.SymedCryptoData;
import org.brekka.phalanx.core.services.SymmetricCryptoService;
import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.CryptoResult;
import org.brekka.phoenix.api.SecretKey;
import org.brekka.phoenix.api.SymmetricCryptoSpec;
import org.brekka.phoenix.core.PhoenixException;
import org.brekka.phoenix.core.model.DefaultSymmetricCryptoSpec;
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
        CryptoProfile profile = cryptoProfileService.retrieveProfile(cryptoData.getProfile());
        InternalSecretKeyToken internalSecretKeyToken = verify(secretKeyToken);
        byte[] data;
        try {
            DefaultSymmetricCryptoSpec spec = new DefaultSymmetricCryptoSpec(internalSecretKeyToken.getSecretKey(), cryptoData.getIv());
            data = phoenixSymmetric.decrypt(cryptoData.getData(), spec);
        } catch (PhoenixException e) {
            throw new PhalanxException(PhalanxErrorCode.CP106, e, 
                    "Failed to decrypt CryptoData with id '%s'", cryptoData.getId());
        }
        return toType(data, expectedType, cryptoData.getId(), profile);
    }


    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public SymedCryptoData encrypt(Object obj, SecretKeyToken secretKeyToken) {
        InternalSecretKeyToken internalSecretKeyToken = verify(secretKeyToken);
        SecretKey secretKey = internalSecretKeyToken.getSecretKey();
        byte[] data = toBytes(obj);
        CryptoResult<SymmetricCryptoSpec> cryptoResult;
        try {
            cryptoResult = phoenixSymmetric.encrypt(data, secretKey);
        } catch (PhoenixException e) {
            throw new PhalanxException(PhalanxErrorCode.CP105, e, 
                    "Failed to symmetric encrypt object");
        }
        
        SymedCryptoData cryptoData = new SymedCryptoData();
        cryptoData.setIv(cryptoResult.getSpec().getIV());
        cryptoData.setData(cryptoResult.getCipherText());
        cryptoData.setProfile(cryptoResult.getSpec().getCryptoProfile().getNumber());
        cryptoDataDAO.create(cryptoData);
        return cryptoData;
    }
    
    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public SecretKeyToken generateSecretKey() {
        CryptoProfile cryptoProfile = cryptoProfileService.retrieveDefault();
        SecretKey secretKey = phoenixSymmetric.createSecretKey(cryptoProfile);
        return new InternalSecretKeyToken(secretKey);
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
    
    public void setCryptoDataDAO(CryptoDataDAO cryptoDataDAO) {
        this.cryptoDataDAO = cryptoDataDAO;
    }
    
}
