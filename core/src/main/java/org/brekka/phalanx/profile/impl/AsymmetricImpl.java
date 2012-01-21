package org.brekka.phalanx.profile.impl;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.Cipher;

import org.brekka.phalanx.CryptoErrorCode;
import org.brekka.phalanx.CryptoException;
import org.brekka.phalanx.profile.CryptoProfile;

class AsymmetricImpl implements CryptoProfile.Asymmetric {

    private final KeyFactory keyFactory;
    
    private final KeyPairGenerator keyPairGenerator;
    
    private final String algorithm;
    
    public AsymmetricImpl() {
        // Keep it low for testing
        this("RSA", 1024);
    }
    
    public AsymmetricImpl(String algorithm, int keySize) {
        this.algorithm = algorithm;
        try {
            this.keyFactory = KeyFactory.getInstance(algorithm);
            this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            this.keyPairGenerator.initialize(keySize);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.CP205, e, 
                    "Key algorithm '%s' not found", algorithm);
        }
    }

    @Override
    public KeyFactory getKeyFactory() {
        return keyFactory;
    }
    
    @Override
    public KeyPair generateKeyPair() {
        return keyPairGenerator.generateKeyPair();
    }

    @Override
    public Cipher getInstance() {
        try {
            return Cipher.getInstance(algorithm);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.CP205, e, 
                    "Asymmetric key algorithm '%s' not found", algorithm);
        }
    }

}
