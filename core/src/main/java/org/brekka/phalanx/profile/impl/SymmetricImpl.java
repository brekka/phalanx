package org.brekka.phalanx.profile.impl;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.brekka.phalanx.CryptoErrorCode;
import org.brekka.phalanx.CryptoException;
import org.brekka.phalanx.profile.CryptoProfile;

class SymmetricImpl implements CryptoProfile.Symmetric {

    private final KeyGenerator keyGenerator;
    
    private final int ivLength;
    
    private final String cipherAlgorithm;
    
    public SymmetricImpl() {
        this("AES", 256, 16, "AES/CBC/PKCS5Padding");
        
    }
    
    public SymmetricImpl(String keyAlgorithm, int keyLength, int ivLength, String cipherAlgorithm) {
        try {
            this.keyGenerator = KeyGenerator.getInstance(keyAlgorithm);
            this.keyGenerator.init(keyLength);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.CP101, e, 
                    "Problem with the symmetric key generator algorithm '%s', key length %d", 
                    keyAlgorithm, keyLength);
        }
        this.ivLength = ivLength;
        this.cipherAlgorithm = cipherAlgorithm;
    }

    @Override
    public KeyGenerator getKeyGenerator() {
        return keyGenerator;
    }

    @Override
    public Cipher getInstance() {
        try {
            return Cipher.getInstance(cipherAlgorithm);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.CP101, e, 
                    "Problem with the symmetric encryption algorithm '%s'", 
                    cipherAlgorithm);
        }
    }

    @Override
    public int getIvLength() {
        return ivLength;
    }

}
