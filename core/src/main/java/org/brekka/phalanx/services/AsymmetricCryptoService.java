package org.brekka.phalanx.services;

import org.brekka.phalanx.model.AsymedCryptoData;
import org.brekka.phalanx.model.AsymmetricKeyPair;
import org.brekka.phalanx.model.Principal;
import org.brekka.phalanx.model.PrivateKeyToken;

public interface AsymmetricCryptoService {
    
    <T> T decrypt(AsymedCryptoData cryptoKey, PrivateKeyToken privateKeyToken, Class<T> expectedType);
    
    PrivateKeyToken decrypt(AsymmetricKeyPair keyPair, String password);
    
    /**
     * Decrypt a keyPair private key using another private key.
     * @param keyPair
     * @param privateKeyToken
     * @return
     */
    PrivateKeyToken decrypt(AsymmetricKeyPair keyPair, PrivateKeyToken privateKeyToken);
    
    /**
     * Encrypt an object 
     * @param data
     * @param keyPair
     * @return
     */
    AsymedCryptoData encrypt(Object data, AsymmetricKeyPair keyPair);
    
    /**
     * Generate a new key pair using the public key of the specified key pair to protect
     * the private key of that being generated.
     * @param protectedWithPublicKeyFrom
     * @return
     */
    AsymmetricKeyPair generateKeyPair(AsymmetricKeyPair protectedWithPublicKeyFrom, Principal owner);
    

    /**
     * Generate a new key pair using a password to protect the private key.
     * @param password
     * @return
     */
    AsymmetricKeyPair generateKeyPair(String password, Principal owner);
    
    /**
     * Assign access to the private key identified by <code>privateKeyToken</code> to the specified
     * user.
     * @param privateKeyToken
     * @param owner
     * @return
     */
    AsymmetricKeyPair assignKeyPair(PrivateKeyToken privateKeyToken, Principal owner);
    
    /**
     * Change a password for the given principal
     * @param principal
     * @param oldPassword
     * @param newPassword
     */
    void changePassword(Principal principal, String oldPassword, String newPassword);
}
