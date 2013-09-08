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

package org.brekka.phalanx.core.services;

import java.util.UUID;

import org.brekka.phalanx.api.model.PrivateKeyToken;
import org.brekka.phalanx.core.model.AsymedCryptoData;
import org.brekka.phalanx.core.model.AsymmetricKeyPair;
import org.brekka.phalanx.core.model.PasswordedCryptoData;
import org.brekka.phalanx.core.model.Principal;

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
     * @param privateKeyToken
     * @param assignToKeyPair
     * @return
     */
    AsymmetricKeyPair assignKeyPair(PrivateKeyToken privateKeyToken, AsymmetricKeyPair assignToKeyPair);
    
    /**
     * @param keyPair
     * @return
     */
    AsymmetricKeyPair cloneKeyPairPublic(AsymmetricKeyPair keyPair);
    

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
