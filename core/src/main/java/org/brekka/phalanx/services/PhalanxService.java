package org.brekka.phalanx.services;

import java.util.UUID;

import org.brekka.phalanx.model.AuthenticatedPrincipal;
import org.brekka.phalanx.model.PrivateKeyToken;

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
    UUID asymEncrypt(byte[] data, UUID keyPairId);
    
    /**
     * Decrypt the specified data item to reveal the 'plain' bytes originally encrypted, using the specified
     * private key token.
     * 
     * @param asymedCryptoDataId id of the data item to decrypt
     * @param privateKeyToken the private key token that can decrypt this data item.
     * @return the unencrypted data.
     */
    byte[] asymDecrypt(UUID asymedCryptoDataId, PrivateKeyToken privateKeyToken);
    
    
    /*
     * Password based crypto operations
     */
    
    /**
     * Encrypt and store piece of data using the specified password.
     * @param data the data to encrypt which should be up to a few kilobytes.
     * @param password the password to use.
     * @return the id of the data item created for the specified data.
     */
    UUID pbeEncrypt(byte[] data, String password);
    
    /**
     * Decrypt the specified data to reveal the 'plain' bytes originally encrypted.
     * @param passwordedCryptoDataId the id of the data instance to decrypt.
     * @param password the password needed to decrypt the data.
     * @return the unencrypted data.
     */
    byte[] pbeDecrypt(UUID passwordedCryptoDataId, String password);
    
    
    /*
     * Key pair operations
     */
    
    /**
     * Decrypt the private key stored within the key pair identified by <code>keyPairId</code>, using the private key
     * token <code>privateKeyToken</code>.
     * @param asymmetricKeyPairId id of the key pair from which to decrypt and extract the private key.
     * @param privateKeyToken the token to use to decrypt.
     * @return the private key token extracted from the requested keyPair.
     */
    PrivateKeyToken decryptKeyPair(UUID asymmetricKeyPairId, PrivateKeyToken privateKeyToken);
    
    /**
     * Create a new key pair which will be protected using the public key from the key pair <code>protectedByKeyPairId</code>.
     * @param protectedByKeyPairId the key pair that will protect the new key pair.
     * @param ownerPrincipalId the owner of the keyPair
     * @return the id of the new key pair.
     */
    UUID generateKeyPair(UUID protectedByKeyPairId, UUID ownerPrincipalId);
    
    /**
     * Assign access to a private key to the specified user.
     * 
     * @param privateKeyToken the token to assign access to
     * @param assignToPrincipalId id of the principal to give access.
     * @return the id of the new key pair that gives the specified principal access to any resources protected by this private key.
     */
    UUID assignKeyPair(PrivateKeyToken privateKeyToken, UUID assignToPrincipalId);
    

    
    /*
     * Deletions
     */
    
    /**
     * Delete a crypto data item.
     * @param cryptoDataItemId if of the data item to delete
     */
    void deleteCryptoDataItem(UUID cryptoDataItemId);
    
    /**
     * Delete a key pair.
     * @param keyPairId id of the key pair to delete
     */
    void deleteKeyPair(UUID keyPairId);
    
    /*
     * Principal
     */
    
    /**
     * Create a new principal with the specified password.
     * @param password the assigned password.
     * @return the new principal id
     */
    UUID createPrincipal(String password);
    
    /**
     * Delete the specified principal.
     * @param principalId
     */
    void deletePrincipal(UUID principalId);
    
    /**
     * Authenticate a principal using the specified password.
     * @param principalId
     * @param password
     * @return the authenticated principal
     */
    AuthenticatedPrincipal authenticate(UUID principalId, String password);
    
    /**
     * Change the password for a principal.
     * @param principalId
     * @param currentPassword
     * @param newPassword
     */
    void changePassword(UUID principalId, String currentPassword, String newPassword);
}
