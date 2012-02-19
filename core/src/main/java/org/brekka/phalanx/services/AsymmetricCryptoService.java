package org.brekka.phalanx.services;

import java.util.UUID;

import org.brekka.phalanx.model.AsymedCryptoData;
import org.brekka.phalanx.model.AsymmetricKeyPair;
import org.brekka.phalanx.model.PasswordedCryptoData;
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
     * Delete the specified key
     * @param cryptoKeyId
     */
    void delete(UUID cryptoKeyId);

    /**
     * Retrieve the specified key pair
     * @param keyPairId
     * @return
     */
    AsymmetricKeyPair retrieveKeyPair(UUID keyPairId);

    /**
     * Delete a key pair
     * @param keyPairId
     */
    void deleteKeyPair(UUID keyPairId);

    /**
     * Replace the private key data of the specified key pair with a new data item.
     * @param keyPair
     * @param privateKeyData
     */
    void replacePrivateKey(AsymmetricKeyPair keyPair, PasswordedCryptoData privateKeyData);
}
