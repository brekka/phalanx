package org.brekka.phalanx.core.services.impl;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

import javax.crypto.Cipher;

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
import org.brekka.phoenix.CryptoFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

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
    public <T> T decrypt(AsymedCryptoData cryptoData, PrivateKeyToken privateKeyToken, Class<T> expectedType) {
        if (privateKeyToken == null) {
            throw new NullPointerException("No private key token supplied");
        }
        cryptoData = (AsymedCryptoData) cryptoDataDAO.retrieveById(cryptoData.getId());
        
        CryptoFactory profile = getCryptoProfileRegistry().getFactory(cryptoData.getProfile());
        InternalPrivateKeyToken ipkt = narrow(privateKeyToken);
        PrivateKey privateKey = ipkt.getPrivateKey();
        
//        AsymmetricKeyPair dataKeyPair = cryptoData.getKeyPair();
//        AsymmetricKeyPair incomingkeyPair = ipkt.getKeyPair();
//        if (!dataKeyPair.getId().equals(incomingkeyPair.getId())) {
//            throw new PhalanxException(PhalanxErrorCode.CP204, 
//                    "The supplied private key '%s' does not match that required to decrypt the key '%s'", 
//                    incomingkeyPair.getPrivateKey().getId(), dataKeyPair.getPrivateKey().getId());
//        }
        
        Cipher asymmetricCipher = getAsymmetricCipher(Cipher.DECRYPT_MODE, privateKey, profile);
        byte[] data;
        try {
            data = asymmetricCipher.doFinal(cryptoData.getData());
        } catch (GeneralSecurityException e) {
            throw new PhalanxException(PhalanxErrorCode.CP211, e,
                    "Failed to decrypt data for CryptoData '%s'", 
                    cryptoData.getId());
        }
        return toType(data, expectedType, cryptoData.getId(), profile);
    }
    
    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void replacePrivateKey(AsymmetricKeyPair keyPair, PasswordedCryptoData newPrivateKeyData) {
        CryptoData originalPrivateKey = keyPair.getPrivateKey();
        keyPair.setPrivateKey(newPrivateKeyData);
        asymetricKeyPairDAO.update(keyPair);
        // Delete the original private key
        cryptoDataDAO.delete(originalPrivateKey.getId());
    }

    private InternalPrivateKeyToken narrow(PrivateKeyToken privateKeyToken) {
        if (privateKeyToken instanceof InternalPrivateKeyToken == false) {
            throw new PhalanxException(PhalanxErrorCode.CP203, 
                    "Private key token must be an instance issued previously by this service. Found '%s'.", 
                    privateKeyToken.getClass().getSimpleName());
        }
        return (InternalPrivateKeyToken) privateKeyToken;
    }
    
    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public AsymedCryptoData encrypt(Object obj, AsymmetricKeyPair keyPair) {
        // Resolve the key pair from persistent storage (could just be id)
        keyPair = asymetricKeyPairDAO.retrieveById(keyPair.getId());
        
        CryptoData publicKeyData = keyPair.getPublicKey();
        PublicKey publicKey = toPublicKey(publicKeyData);
        byte[] data = toBytes(obj);
        
        CryptoFactory profile = getCryptoProfileRegistry().getDefault();
        
        Cipher asymmetricCipher = getAsymmetricCipher(Cipher.ENCRYPT_MODE, publicKey, profile);
        byte[] cipherData;
        try {
            cipherData = asymmetricCipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new PhalanxException(PhalanxErrorCode.CP212, e,
                    "Failed to encrypt data from object of type '%s' using key pair '%s'", 
                    obj.getClass().getName(), keyPair.getId());
        }
        
        AsymedCryptoData encryptedData = new AsymedCryptoData();
        encryptedData.setData(cipherData);
        encryptedData.setKeyPair(keyPair);
        encryptedData.setProfile(profile.getProfileId());
        cryptoDataDAO.create(encryptedData);
        return encryptedData;
    }
    
    @Override
    public void delete(UUID cryptoKeyId) {
        cryptoDataDAO.delete(cryptoKeyId);
    }
    
    
    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public PrivateKeyToken decrypt(AsymmetricKeyPair keyPair, String password) {
     // Resolve the key pair from persistent storage (could just be id)
        keyPair = asymetricKeyPairDAO.retrieveById(keyPair.getId());
        
        CryptoData privateKey = keyPair.getPrivateKey();
        if (privateKey instanceof PasswordedCryptoData == false) {
            throw new PhalanxException(PhalanxErrorCode.CP209, 
                    "Key pair '%s' private key is not password protected", keyPair.getId());
        }
        PasswordedCryptoData passwordedCryptoData = (PasswordedCryptoData) privateKey;
        InternalSecretKeyToken secretKeyToken = passwordBasedCryptoService.decrypt(
                passwordedCryptoData, password, InternalSecretKeyToken.class);
        return symDecryptForPrivateKey(secretKeyToken, keyPair);
    }
    
    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public PrivateKeyToken decrypt(AsymmetricKeyPair keyPair, PrivateKeyToken privateKeyToken) {
        // Resolve the key pair from persistent storage (could just be id)
        keyPair = asymetricKeyPairDAO.retrieveById(keyPair.getId());
        
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
    public AsymmetricKeyPair generateKeyPair(AsymmetricKeyPair protectedWithPublicKeyFrom, Principal owner) {
        // Resolve the key pair from persistent storage (could just be id)
        protectedWithPublicKeyFrom = asymetricKeyPairDAO.retrieveById(protectedWithPublicKeyFrom.getId());
        
        CryptoFactory profile = getCryptoProfileRegistry().getDefault();
        CryptoFactory.Asymmetric asynchronousProfile = profile.getAsymmetric();
        KeyPair keyPair = asynchronousProfile.generateKeyPair();
        
        CryptoData publicKeyData = toPublicKey(keyPair.getPublic(), profile.getProfileId());
        InternalPrivateKeyToken internalPrivateKey = new InternalPrivateKeyToken(keyPair.getPrivate(), profile.getProfileId());
        InternalSecretKeyToken secretKeyToken = symEncryptPrivateKey(internalPrivateKey);
        
        AsymedCryptoData privateKeyData = encrypt(secretKeyToken, protectedWithPublicKeyFrom);
        AsymmetricKeyPair asymKeyPair = new AsymmetricKeyPair();
        asymKeyPair.setPrivateKey(privateKeyData);
        asymKeyPair.setPublicKey(publicKeyData);
        asymKeyPair.setOwner(owner);
        asymetricKeyPairDAO.create(asymKeyPair);
        
        return asymKeyPair;
    }

    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public AsymmetricKeyPair generateKeyPair(String passwordToProtectPrivateKey, Principal owner) {
        CryptoFactory profile = getCryptoProfileRegistry().getDefault();
        CryptoFactory.Asymmetric asymmetricProfile = profile.getAsymmetric();
        KeyPair keyPair = asymmetricProfile.generateKeyPair();
        
        CryptoData publicKeyData = toPublicKey(keyPair.getPublic(), profile.getProfileId());
        InternalPrivateKeyToken internalPrivateKey = new InternalPrivateKeyToken(keyPair.getPrivate(), profile.getProfileId());
        InternalSecretKeyToken secretKeyToken = symEncryptPrivateKey(internalPrivateKey);
        
        PasswordedCryptoData privateKeyData = passwordBasedCryptoService.encrypt(secretKeyToken, passwordToProtectPrivateKey);
        AsymmetricKeyPair asymKeyPair = new AsymmetricKeyPair();
        asymKeyPair.setPrivateKey(privateKeyData);
        asymKeyPair.setPublicKey(publicKeyData);
        asymKeyPair.setOwner(owner);
        asymetricKeyPairDAO.create(asymKeyPair);
        
        return asymKeyPair;
    }
    
    @Override
    public AsymmetricKeyPair assignKeyPair(PrivateKeyToken privateKeyToken, Principal owner) {
        AsymmetricKeyPair keyPair = (AsymmetricKeyPair) privateKeyToken.getKeyPair();
        InternalPrivateKeyToken internalPrivateKeyToken = narrow(privateKeyToken);
        InternalSecretKeyToken secretKey = internalPrivateKeyToken.getSecretKey();
        
        owner = principalDAO.retrieveById(owner.getId());
        
        AsymedCryptoData privateKeyData = encrypt(secretKey, owner.getDefaultKeyPair());
        AsymmetricKeyPair asymKeyPair = new AsymmetricKeyPair();
        asymKeyPair.setPrivateKey(privateKeyData);
        asymKeyPair.setPublicKey(keyPair.getPublicKey());
        asymKeyPair.setOwner(owner);
        asymetricKeyPairDAO.create(asymKeyPair);
        return asymKeyPair;
    }
    
    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public AsymmetricKeyPair retrieveKeyPair(UUID keyPairId) {
        return asymetricKeyPairDAO.retrieveById(keyPairId);
    }
    
    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public void deleteKeyPair(UUID keyPairId) {
        asymetricKeyPairDAO.delete(keyPairId);
    }
    
    protected PublicKey toPublicKey(CryptoData publicKeyData) {
        CryptoFactory profile = getCryptoProfileRegistry().getFactory(publicKeyData.getProfile());
        if (publicKeyData.getClass() != CryptoData.class) {
            throw new PhalanxException(PhalanxErrorCode.CP201, 
                    "CryptoData item '%s' is not plain", publicKeyData.getId());
        }
        byte[] data = publicKeyData.getData();
        return toType(data, PublicKey.class, publicKeyData.getId(), profile);
    }
    
    protected CryptoData toPublicKey(PublicKey publicKey, int profileId) {
        CryptoData publicKeyData = new CryptoData();
        publicKeyData.setData(publicKey.getEncoded());
        publicKeyData.setProfile(profileId);
        cryptoDataDAO.create(publicKeyData);
        return publicKeyData;
    }
    
    protected Cipher getAsymmetricCipher(int mode, Key key, CryptoFactory cryptoProfile) {
        Cipher cipher = cryptoProfile.getAsymmetric().getInstance();
        try {
            cipher.init(mode, key);
        } catch (InvalidKeyException e) {
            throw new PhalanxException(PhalanxErrorCode.CP206, e, 
                    "Problem initializing asymmetric cipher");
        }
        return cipher;
    }
    
    protected SymedCryptoData narrow(CryptoData cryptoData) {
        if (cryptoData instanceof SymedCryptoData == false) {
            throw new PhalanxException(PhalanxErrorCode.CP212, 
                    "The CryptoData used to store the private key is not a SymCryptoData, it is instead '%s'", 
                    cryptoData.getClass().getName());
        }
        SymedCryptoData symedCryptoData = (SymedCryptoData) cryptoData;
        return symedCryptoData;
    }
    

    protected PrivateKeyToken symDecryptForPrivateKey(InternalSecretKeyToken secretKeyToken, AsymmetricKeyPair keyPair) {
        UUID symDataId = secretKeyToken.getSymedCryptoData().getId();
        CryptoData cryptoData = cryptoDataDAO.retrieveById(symDataId);
        SymedCryptoData symedCryptoData = narrow(cryptoData);
        InternalPrivateKeyToken privateKeyToken = symmetricCryptoService.decrypt(symedCryptoData, secretKeyToken, InternalPrivateKeyToken.class);
        privateKeyToken.setSecretKey(secretKeyToken);
        privateKeyToken.setAsymetricKeyPair(keyPair);
        return privateKeyToken;
    }
    
    protected InternalSecretKeyToken symEncryptPrivateKey(InternalPrivateKeyToken internalPrivateKey) {
        InternalSecretKeyToken secretKeyToken = (InternalSecretKeyToken) symmetricCryptoService.generateSecretKey();
        SymedCryptoData symedCryptoData = symmetricCryptoService.encrypt(internalPrivateKey, secretKeyToken);
        secretKeyToken.setSymedCryptoData(symedCryptoData);
        internalPrivateKey.setSecretKey(secretKeyToken);
        return secretKeyToken;
    }
    
    
    
    public void setAsymetricKeyPairDAO(AsymmetricKeyPairDAO asymetricKeyPairDAO) {
        this.asymetricKeyPairDAO = asymetricKeyPairDAO;
    }
    
    public void setCryptoDataDAO(CryptoDataDAO cryptoDataDAO) {
        this.cryptoDataDAO = cryptoDataDAO;
    }
    
    public void setPasswordBasedCryptoService(PasswordBasedCryptoService passwordBasedCryptoService) {
        this.passwordBasedCryptoService = passwordBasedCryptoService;
    }
    
    public void setSymmetricCryptoService(SymmetricCryptoService symmetricCryptoService) {
        this.symmetricCryptoService = symmetricCryptoService;
    }
}
