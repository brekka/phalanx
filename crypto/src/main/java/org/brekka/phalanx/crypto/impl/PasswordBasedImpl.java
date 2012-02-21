package org.brekka.phalanx.crypto.impl;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;

import org.brekka.phalanx.crypto.CryptoErrorCode;
import org.brekka.phalanx.crypto.CryptoException;
import org.brekka.phalanx.crypto.CryptoFactory;
import org.brekka.xml.phalanx.v1.crypto.PasswordBasedProfileType;

class PasswordBasedImpl implements CryptoFactory.PasswordBased {
    
    private final SecretKeyFactory secretKeyFactory;
    
    private final int saltLength;
    
    private final int iterationFactor;
    
    private final String algorithm;
    
    
    public PasswordBasedImpl(PasswordBasedProfileType profile) {
        this(
            profile.getCipher().getAlgorithm().getStringValue(),
            profile.getSecretKeyFactory().getAlgorithm().getStringValue(),
            profile.getSaltLength(),
            profile.getIterationFactor()
        );
    }
    
    public PasswordBasedImpl(String cipherAlgorithm, String secretKeyAlgorithm, int saltLength, int iterationFactor) {
        try {
            this.secretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.CP300, e, 
                    "Failed to prepare key factory with algorithm '%s'", secretKeyAlgorithm);
        }
        this.saltLength = saltLength;
        this.iterationFactor = iterationFactor;
        this.algorithm = cipherAlgorithm;
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
