package org.brekka.phalanx.services.impl;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

import javax.crypto.Cipher;

import org.brekka.phalanx.CryptoErrorCode;
import org.brekka.phalanx.CryptoException;
import org.brekka.phalanx.dao.AsymmetricKeyPairDAO;
import org.brekka.phalanx.dao.CryptoDataDAO;
import org.brekka.phalanx.model.AsymedCryptoData;
import org.brekka.phalanx.model.AsymmetricKeyPair;
import org.brekka.phalanx.model.CryptoData;
import org.brekka.phalanx.model.PasswordedCryptoData;
import org.brekka.phalanx.model.Principal;
import org.brekka.phalanx.model.PrivateKeyToken;
import org.brekka.phalanx.model.SymedCryptoData;
import org.brekka.phalanx.profile.CryptoProfile;
import org.brekka.phalanx.services.AsymmetricCryptoService;
import org.brekka.phalanx.services.PasswordBasedCryptoService;
import org.brekka.phalanx.services.SymmetricCryptoService;
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
    

    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public <T> T decrypt(AsymedCryptoData cryptoData, PrivateKeyToken privateKeyToken, Class<T> expectedType) {
        if (privateKeyToken == null) {
            throw new NullPointerException("No private key token supplied");
        }
        if (privateKeyToken instanceof InternalPrivateKeyToken == false) {
            throw new CryptoException(CryptoErrorCode.CP203, 
                    "Private key token must be an instance issued previously by this service. Found '%s'.", 
                    privateKeyToken.getClass().getSimpleName());
        }
        CryptoProfile profile = getCryptoProfileRegistry().getProfile(cryptoData.getProfile());
        InternalPrivateKeyToken ipkt = (InternalPrivateKeyToken) privateKeyToken;
        PrivateKey privateKey = ipkt.getPrivateKey();
        
        AsymmetricKeyPair dataKeyPair = cryptoData.getKeyPair();
        AsymmetricKeyPair incomingkeyPair = ipkt.getKeyPair();
        if (!dataKeyPair.getId().equals(incomingkeyPair.getId())) {
            throw new CryptoException(CryptoErrorCode.CP204, 
                    "The supplied private key '%s' does not match that required to decrypt the key '%s'", 
                    incomingkeyPair.getPrivateKey().getId(), dataKeyPair.getPrivateKey().getId());
        }
        
        Cipher asymmetricCipher = getAsymmetricCipher(Cipher.DECRYPT_MODE, privateKey, profile);
        byte[] data;
        try {
            data = asymmetricCipher.doFinal(cryptoData.getData());
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.CP211, e,
                    "Failed to decrypt data for CryptoData '%s'", 
                    cryptoData.getId());
        }
        return toType(data, expectedType, cryptoData.getId(), profile);
    }
    
    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public AsymedCryptoData encrypt(Object obj, AsymmetricKeyPair keyPair) {
        CryptoData publicKeyData = keyPair.getPublicKey();
        PublicKey publicKey = toPublicKey(publicKeyData);
        byte[] data = toBytes(obj);
        
        CryptoProfile profile = getCryptoProfileRegistry().getDefaultProfile();
        
        Cipher asymmetricCipher = getAsymmetricCipher(Cipher.ENCRYPT_MODE, publicKey, profile);
        byte[] cipherData;
        try {
            cipherData = asymmetricCipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.CP212, e,
                    "Failed to encrypt data using key pair '%s'", 
                    keyPair.getId());
        }
        
        AsymedCryptoData encryptedData = new AsymedCryptoData();
        encryptedData.setData(cipherData);
        encryptedData.setKeyPair(keyPair);
        cryptoDataDAO.create(encryptedData);
        return encryptedData;
    }
    
    
    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public PrivateKeyToken decrypt(AsymmetricKeyPair keyPair, String password) {
        CryptoData privateKey = keyPair.getPrivateKey();
        if (privateKey instanceof PasswordedCryptoData == false) {
            throw new CryptoException(CryptoErrorCode.CP209, 
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
        CryptoData privateKey = keyPair.getPrivateKey();
        if (privateKey instanceof AsymedCryptoData == false) {
            throw new CryptoException(CryptoErrorCode.CP210, 
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
        CryptoProfile profile = getCryptoProfileRegistry().getDefaultProfile();
        CryptoProfile.Asymmetric asynchronousProfile = profile.getAsymmetric();
        KeyPair keyPair = asynchronousProfile.generateKeyPair();
        
        CryptoData publicKeyData = toPublicKey(keyPair.getPublic(), profile.getId());
        InternalPrivateKeyToken internalPrivateKey = new InternalPrivateKeyToken(keyPair.getPrivate(), profile.getId());
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
        CryptoProfile profile = getCryptoProfileRegistry().getDefaultProfile();
        CryptoProfile.Asymmetric asymmetricProfile = profile.getAsymmetric();
        KeyPair keyPair = asymmetricProfile.generateKeyPair();
        
        CryptoData publicKeyData = toPublicKey(keyPair.getPublic(), profile.getId());
        InternalPrivateKeyToken internalPrivateKey = new InternalPrivateKeyToken(keyPair.getPrivate(), profile.getId());
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
        AsymmetricKeyPair keyPair = privateKeyToken.getKeyPair();
        SymedCryptoData symedCryptoData = narrow(keyPair.getPrivateKey());
        
        AsymedCryptoData privateKeyData = encrypt(symedCryptoData, owner.getDefaultKeyPair());
        AsymmetricKeyPair asymKeyPair = new AsymmetricKeyPair();
        asymKeyPair.setPrivateKey(privateKeyData);
        asymKeyPair.setPublicKey(keyPair.getPublicKey());
        asymKeyPair.setOwner(owner);
        asymetricKeyPairDAO.create(asymKeyPair);
        return asymKeyPair;
    }
    
    protected PublicKey toPublicKey(CryptoData publicKeyData) {
        CryptoProfile profile = getCryptoProfileRegistry().getProfile(publicKeyData.getProfile());
        if (publicKeyData.getClass() != CryptoData.class) {
            throw new CryptoException(CryptoErrorCode.CP201, 
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
    
    protected Cipher getAsymmetricCipher(int mode, Key key, CryptoProfile cryptoProfile) {
        Cipher cipher = cryptoProfile.getAsymmetric().getInstance();
        try {
            cipher.init(mode, key);
        } catch (InvalidKeyException e) {
            throw new CryptoException(CryptoErrorCode.CP206, e, 
                    "Problem initializing asymmetric cipher");
        }
        return cipher;
    }
    
    protected SymedCryptoData narrow(CryptoData cryptoData) {
        if (cryptoData instanceof SymedCryptoData == false) {
            throw new CryptoException(CryptoErrorCode.CP212, 
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
        privateKeyToken.setAsymetricKeyPair(keyPair);
        return privateKeyToken;
    }
    
    protected InternalSecretKeyToken symEncryptPrivateKey(InternalPrivateKeyToken internalPrivateKey) {
        InternalSecretKeyToken secretKeyToken = (InternalSecretKeyToken) symmetricCryptoService.generateSecretKey();
        SymedCryptoData symedCryptoData = symmetricCryptoService.encrypt(internalPrivateKey, secretKeyToken);
        secretKeyToken.setSymedCryptoData(symedCryptoData);
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
