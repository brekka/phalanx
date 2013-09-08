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

package org.brekka.phalanx.core.services.impl;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.api.model.PrivateKeyToken;
import org.brekka.phalanx.core.services.PhalanxSessionService;
import org.brekka.phoenix.api.services.RandomCryptoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PhalanxSessionServiceImpl implements PhalanxSessionService {
    private static final int SESSION_ID_LENGTH = 24;

    private static final int PK_KEY_LENGTH = 3;
    

    private final Map<CacheKey, PrincipalSession> cache = new ConcurrentHashMap<>();
    
    private final ThreadLocal<PrincipalSession> context = new ThreadLocal<>();
    
    
    @Autowired
    private RandomCryptoService randomCryptoService;
    
    /* (non-Javadoc)
     * @see org.brekka.phalanx.web.support.PhalanxSessionCache#registerPrivateKey(org.brekka.phalanx.model.PrivateKeyToken)
     */
    @Override
    public byte[] registerPrivateKey(PrivateKeyToken privateKey) {
        byte[] key = getCurrent().registerPrivateKey(privateKey);
        return key;
    }

    /* (non-Javadoc)
     * @see org.brekka.phalanx.web.support.PhalanxSessionCache#allocateAndBind(org.brekka.phalanx.model.AuthenticatedPrincipal)
     */
    @Override
    public byte[] allocateAndBind(AuthenticatedPrincipal authenticatedPrincipal) {
        SecureRandom secureRandom = randomCryptoService.getSecureRandom();
        byte[] keyBytes = new byte[SESSION_ID_LENGTH];
        secureRandom.nextBytes(keyBytes);
        CacheKey key = new CacheKey(keyBytes);
        PrincipalSession principalSession = new PrincipalSession(authenticatedPrincipal);
        cache.put(key, principalSession);
        context.set(principalSession);
        return keyBytes;
    }
    
    @Override
    public void logout(byte[] sessionID) {
        cache.remove(new CacheKey(sessionID));
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phalanx.web.support.PhalanxSessionCache#bind(byte[])
     */
    @Override
    public void bind(byte[] sessionId) {
        CacheKey key = new CacheKey(sessionId);
        PrincipalSession cached = cache.get(key);
        context.set(cached);
    } 

    /* (non-Javadoc)
     * @see org.brekka.phalanx.web.support.PhalanxSessionCache#unbind()
     */
    @Override
    public void unbind() {
        context.remove();
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phalanx.web.support.PhalanxSessionCache#resolvePrivateKey(java.lang.String)
     */
    @Override
    public PrivateKeyToken retrievePrivateKey(byte[] key) {
        return getCurrent().retrievePrivateKey(key);
    }
    
    @Override
    public AuthenticatedPrincipal getCurrentPrincipal() {
        return getCurrent().getAuthenticatedPrincipal();
    }
    
    private PrincipalSession getCurrent() {
        return context.get();
    }

    
    private class PrincipalSession {
        

        private final AuthenticatedPrincipal authenticatedPrincipal;
        
        private final Map<CacheKey, PrivateKeyToken> privateKeys = new HashMap<>();

        public PrincipalSession(AuthenticatedPrincipal authenticatedPrincipal) {
            this.authenticatedPrincipal = authenticatedPrincipal;
        }
        
        public byte[] registerPrivateKey(PrivateKeyToken privateKey) {
            SecureRandom secureRandom = randomCryptoService.getSecureRandom();
            byte[] keyBytes = new byte[PK_KEY_LENGTH];
            secureRandom.nextBytes(keyBytes);
            CacheKey key = new CacheKey(keyBytes);
            privateKeys.put(key, privateKey);
            return keyBytes;
        }

        public PrivateKeyToken retrievePrivateKey(byte[] key) {
            return privateKeys.get(new CacheKey(key));
        }

        public AuthenticatedPrincipal getAuthenticatedPrincipal() {
            return authenticatedPrincipal;
        }
    }
    

    private static class CacheKey {
        private final byte[] b;
        
        public CacheKey(byte[] b) {
            this.b = b;
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(b);
        }
        
        @Override
        public boolean equals(Object obj) {
            return Arrays.equals(b, ((CacheKey) obj).b);
        }
    }
}
