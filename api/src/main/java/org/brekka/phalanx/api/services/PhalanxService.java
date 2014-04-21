/*
 * Copyright 2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.brekka.phalanx.api.services;

import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.api.model.CryptedData;
import org.brekka.phalanx.api.model.ExportedPublicKey;
import org.brekka.phalanx.api.model.KeyPair;
import org.brekka.phalanx.api.model.Principal;
import org.brekka.phalanx.api.model.PrivateKeyToken;
import org.w3c.dom.Document;

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
     * Encrypt and store piece of data using the public key of the principal identified by <code>recipientPrincipal</code>.
     * @param data the data to encrypt which should be up to a few kilobytes.
     * @param recipientPrincipal id of the principal whose public key will be used to encrypt the data.
     * @return the id of the encrypted data item.
     */
    CryptedData asymEncrypt(byte[] data, Principal recipientPrincipal);

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
     * Create a new key pair which will be protected using the public key from the key pair <code>protectedByKeyPairId</code>. It will not be
     * assigned to any principal.
     * @param protectedByKeyPair the key pair that will protect the new key pair.
     * @return the new key pair.
     */
    KeyPair generateKeyPair(KeyPair protectedByKeyPair);

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

    /**
     * Create a new key pair assignment that will be protected by the specified key pair
     *
     * @param privateKeyToken the token to assign access to
     * @param assignToKeyPair the key pair to assign to.
     * @return the id of the new key pair that gives the specified principal access to any resources protected by this private key.
     */
    KeyPair assignKeyPair(PrivateKeyToken privateKeyToken, KeyPair assignToKeyPair);

    /**
     * Create a copy of the specfied keypair containing only the public key.
     *
     * @param associateDivisionKeyPair
     * @return
     */
    KeyPair cloneKeyPairPublic(KeyPair keyPair);

    /**
     * Retrieve the actual public key in its standard byte array representation.
     * @param keyPair the key pair from which to return the public key
     * @return the public key part of the key pair in its standard byte array form.
     */
    ExportedPublicKey retrievePublicKey(KeyPair keyPair);

    /**
     * Retrieve the actual public key in its standard byte array representation of the specified principals default key pair.
     * @param principal the principal from whom to extract the public key based on their default key pair.
     * @return the public key part of the default key pair in its standard byte array form.
     */
    ExportedPublicKey retrievePublicKey(Principal principal);

    /**
     * Sign the specified document using the private key
     *
     * @param document
     * @param privateKeyToken
     * @return the now signed document
     */
    Document sign(Document document, PrivateKeyToken privateKeyToken);

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
     * Clear the session for the specified principal.
     * @param authenticatedPrincipal
     */
    void logout(AuthenticatedPrincipal authenticatedPrincipal);

    /**
     * Change the password for a principal.
     * @param principalId
     * @param currentPassword
     * @param newPassword
     */
    void changePassword(Principal principal, String currentPassword, String newPassword);
}
