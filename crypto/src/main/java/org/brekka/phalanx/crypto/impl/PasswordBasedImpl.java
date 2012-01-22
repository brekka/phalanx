package org.brekka.phalanx.crypto.impl;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;

import org.brekka.phalanx.crypto.CryptoErrorCode;
import org.brekka.phalanx.crypto.CryptoException;
import org.brekka.phalanx.crypto.CryptoFactory;

class PasswordBasedImpl implements CryptoFactory.PasswordBased {
    
    private final SecretKeyFactory secretKeyFactory;
    
    private final int saltLength;
    
    private final int iterationFactor;
    
    private final String algorithm;
    
    
    public PasswordBasedImpl() {
        this("PBEWITHSHA256AND256BITAES-CBC-BC", 32, 20);
    }
    
    public PasswordBasedImpl(String algorithm, int saltLength, int iterationFactor) {
        try {
            this.secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.CP300, e, 
                    "Failed to prepare key factory with algorithm '%s'", algorithm);
        }
        this.saltLength = saltLength;
        this.iterationFactor = iterationFactor;
        this.algorithm = algorithm;
    }

    @Override
    public SecretKeyFactory getSecretKeyFactory() {
        return secretKeyFactory;
    }

    @Override
    public int getSaltLength() {
        return saltLength;
    }

    @Override
    public int getIterationFactor() {
        return iterationFactor;
    }

    @Override
    public Cipher getInstance() {
        try {
            return Cipher.getInstance(algorithm);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.CP300, e, 
                    "Failed to prepare key factory/cipher with algorithm '%s'", algorithm);
        }
    }

}
