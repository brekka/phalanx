package org.brekka.phalanx.crypto.impl;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.brekka.phalanx.crypto.CryptoErrorCode;
import org.brekka.phalanx.crypto.CryptoException;
import org.brekka.phalanx.crypto.CryptoFactory;
import org.brekka.xml.v1.phalanx.SymmetricProfileType;

class SymmetricImpl implements CryptoFactory.Symmetric {

    private final KeyGenerator keyGenerator;
    
    private final int ivLength;
    
    private final String algorithm;
    
    public SymmetricImpl(SymmetricProfileType profile) {
        this(
            profile.getCipher().getAlgorithm().getStringValue(),
            profile.getKeyGenerator().getAlgorithm().getStringValue(),
            profile.getKeyGenerator().getKeyLength(),
            profile.getIVLength()
        );
    }
    
    public SymmetricImpl(String cipherAlgorithm, String keyAlgorithm, int keyLength, int ivLength) {
        try {
            this.keyGenerator = KeyGenerator.getInstance(keyAlgorithm);
            this.keyGenerator.init(keyLength);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.CP101, e, 
                    "Problem with the symmetric key generator algorithm '%s', key length %d", 
                    keyAlgorithm, keyLength);
        }
        this.ivLength = ivLength;
        this.algorithm = cipherAlgorithm;
    }

    @Override
    public KeyGenerator getKeyGenerator() {
        return keyGenerator;
    }

    @Override
    public Cipher getInstance() {
        try {
            return Cipher.getInstance(algorithm);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.CP101, e, 
                    "Problem with the symmetric encryption algorithm '%s'", 
                    algorithm);
        }
    }

    @Override
    public int getIvLength() {
        return ivLength;
    }

}
