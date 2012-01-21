package org.brekka.phalanx.profile.impl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.brekka.phalanx.CryptoErrorCode;
import org.brekka.phalanx.CryptoException;
import org.brekka.phalanx.profile.CryptoProfile;

public class CryptoProfileImpl implements CryptoProfile {

    private final int id;
    
    private final String messageDigestAlgorithm;
    
    private final SecureRandom secureRandom;
    
    private final Asymmetric asynchronous;
    
    private final PasswordBased passwordBased;
    
    private final Symmetric synchronous;
    
    CryptoProfileImpl() {
        this(0, "SHA-256", "NativePRNG", new AsymmetricImpl(), new PasswordBasedImpl(), new SymmetricImpl());
    }
    
    public CryptoProfileImpl(int id, String messageDigestAlgorithm, String secureRandomAlgorithm, 
            Asymmetric asynchronous, PasswordBased passwordBased, Symmetric synchronous) {
        this.id = id;
        this.messageDigestAlgorithm = messageDigestAlgorithm;
        try {
            this.secureRandom = SecureRandom.getInstance(secureRandomAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(CryptoErrorCode.CP400, e, 
                    "Secure random algorithm '%s' not found", secureRandomAlgorithm);
        }
        this.asynchronous = asynchronous;
        this.passwordBased = passwordBased;
        this.synchronous = synchronous;
    }

    @Override
    public int getId() {
        return id;
    }

    @Override
    public MessageDigest getDigestInstance() {
        try {
            return MessageDigest.getInstance(messageDigestAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(CryptoErrorCode.CP100, e, 
                    "Message digest algorithm '%s' not found", messageDigestAlgorithm);
        }
    }
    
    @Override
    public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    @Override
    public Asymmetric getAsymmetric() {
        return asynchronous;
    }

    @Override
    public PasswordBased getPasswordBased() {
        return passwordBased;
    }

    @Override
    public Symmetric getSymmetric() {
        return synchronous;
    }

}
