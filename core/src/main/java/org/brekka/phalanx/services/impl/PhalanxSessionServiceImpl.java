package org.brekka.phalanx.services.impl;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.brekka.phalanx.model.AuthenticatedPrincipal;
import org.brekka.phalanx.model.PrivateKeyToken;
import org.brekka.phalanx.services.PhalanxSessionService;
import org.brekka.phoenix.CryptoFactoryRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PhalanxSessionServiceImpl implements PhalanxSessionService {

    private final Map<CacheKey, PrincipalSession> cache = new ConcurrentHashMap<>();
    
    private final ThreadLocal<PrincipalSession> context = new ThreadLocal<>();
    
    @Autowired
    private CryptoFactoryRegistry cryptoProfileRegistry;
    
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
        SecureRandom secureRandom = cryptoProfileRegistry.getDefault().getSecureRandom();
        byte[] keyBytes = new byte[32];
        secureRandom.nextBytes(keyBytes);
        CacheKey key = new CacheKey(keyBytes);
        cache.put(key, new PrincipalSession(authenticatedPrincipal));
        return keyBytes;
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phalanx.web.support.PhalanxSessionCache#bind(byte[])
     */
    @Override
    public void bind(byte[] sessionId) {
        CacheKey key = new CacheKey(sessionId);
        if (key != null) {
            PrincipalSession cached = cache.get(key);
            context.set(cached);
        }
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
            SecureRandom secureRandom = cryptoProfileRegistry.getDefault().getSecureRandom();
            byte[] keyBytes = new byte[4];
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
            return Arrays.equals(b, (byte[]) obj);
        }
    }
}
