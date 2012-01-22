package org.brekka.phalanx.crypto;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;

public interface CryptoFactory {

    int getProfileId();
    
    MessageDigest getDigestInstance();
    
    SecureRandom getSecureRandom();
    
    Symmetric getSymmetric();
    
    Asymmetric getAsymmetric();
    
    PasswordBased getPasswordBased();
    

    
    
    interface Asymmetric {
        KeyFactory getKeyFactory();
        
        KeyPair generateKeyPair();
        
        Cipher getInstance();
    }
    
    interface PasswordBased {
        SecretKeyFactory getSecretKeyFactory();
        
        int getSaltLength();
        
        int getIterationFactor();
        
        Cipher getInstance();
    }
    
    interface Symmetric {
        KeyGenerator getKeyGenerator();
        
        Cipher getInstance();
        
        int getIvLength();
    }
}
