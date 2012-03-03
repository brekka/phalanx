package org.brekka.phalanx.api.services;

import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.api.model.CryptedData;
import org.brekka.phalanx.api.model.KeyPair;
import org.brekka.phalanx.api.model.Principal;
import org.brekka.phalanx.api.model.PrivateKeyToken;

/**
 * Publicly exposed operations for the Phalanx service
 * 
 * @author Andrew Taylor
 */
public interface PhalanxService {

    /*
     * Asymmetric crypto operations
     */
    
    /**
     * Encrypt and store piece of data using the public key of the key pair identified by <code>keyPairId</code>.
     * @param data the data to encrypt which should be up to a few kilobytes. 
     * @param keyPairId id of the keyPair whose public key will be used to encrypt the data.
     * @return the id of the encrypted data item.
     */
    CryptedData asymEncrypt(byte[] data, KeyPair keyPairId);
    
    /**
     * Decrypt the specified data item to reveal the 'plain' bytes originally encrypted, using the specified
     * private key token.
     * 
     * @param asymedCryptoData the data item to decrypt
     * @param privateKeyToken the private key token that can decrypt this data item.
     * @return the unencrypted data.
     */
    byte[] asymDecrypt(CryptedData asymedCryptoData, PrivateKeyToken privateKeyToken);
    
    
    /*
     * Password based crypto operations
     */
    
    /**
     * Encrypt and store piece of data using the specified password.
     * @param data the data to encrypt which should be up to a few kilobytes.
     * @param password the password to use.
     * @return the the data item created for the specified data.
     */
    CryptedData pbeEncrypt(byte[] data, String password);
    
    /**
     * Decrypt the specified data to reveal the 'plain' bytes originally encrypted.
     * @param passwordedCryptoData the id of the data instance to decrypt.
     * @param password the password needed to decrypt the data.
     * @return the unencrypted data.
     */
    byte[] pbeDecrypt(CryptedData passwordedCryptoData, String password);
    
    
    /*
     * Key pair operations
     */
    
    /**
     * Decrypt the private key stored within the key pair identified by <code>keyPairId</code>, using the private key
     * token <code>privateKeyToken</code>.
     * @param keyPair key pair from which to decrypt and extract the private key.
     * @param privateKeyToken the token to use to decrypt.
     * @return the private key token extracted from the requested keyPair.
     */
    PrivateKeyToken decryptKeyPair(KeyPair keyPair, PrivateKeyToken privateKeyToken);
    
    /**
     * Create a new key pair which will be protected using the public key from the key pair <code>protectedByKeyPairId</code>.
     * @param protectedByKeyPair the key pair that will protect the new key pair.
     * @param ownerPrincipal the owner of the keyPair
     * @return the new key pair.
     */
    KeyPair generateKeyPair(KeyPair protectedByKeyPair, Principal ownerPrincipal);
    
    /**
     * Assign access to a private key to the specified user.
     * 
     * @param privateKeyToken the token to assign access to
     * @param assignToPrincipal id of the principal to give access.
     * @return the id of the new key pair that gives the specified principal access to any resources protected by this private key.
     */
    KeyPair assignKeyPair(PrivateKeyToken privateKeyToken, Principal assignToPrincipal);
    

    
    /*
     * Deletions
     */
    
    /**
     * Delete a crypto data item.
     * @param cryptoDataItemId if of the data item to delete
     */
    void deleteCryptedData(CryptedData cryptedDataItem);
    
    /**
     * Delete a key pair.
     * @param keyPairId id of the key pair to delete
     */
    void deleteKeyPair(KeyPair keyPairId);
    
    /*
     * Principal
     */
    
    /**
     * Create a new principal with the specified password.
     * @param password the assigned password.
     * @return the new principal id
     */
    Principal createPrincipal(String password);
    
    /**
     * Delete the specified principal.
     * @param principal
     */
    void deletePrincipal(Principal principal);
    
    /**
     * Authenticate a principal using the specified password.
     * @param principalId
     * @param password
     * @return the authenticated principal
     */
    AuthenticatedPrincipal authenticate(Principal principal, String password);
    
    /**
     * Change the password for a principal.
     * @param principalId
     * @param currentPassword
     * @param newPassword
     */
    void changePassword(Principal principal, String currentPassword, String newPassword);
}
