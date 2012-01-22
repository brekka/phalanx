package org.brekka.phalanx.crypto.impl;

import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.brekka.phalanx.crypto.CryptoFactory;
import org.brekka.phalanx.crypto.CryptoFactoryRegistry;

public class CryptoFactoryRegistryImpl implements CryptoFactoryRegistry {

    private CryptoFactory defaultProfile;
    
    private Map<Integer, CryptoFactory> profileMap = new HashMap<>();
    
    public CryptoFactoryRegistryImpl(CryptoFactory defaultProfile, CryptoFactory... others) {
        this.defaultProfile = defaultProfile;
        profileMap.put(defaultProfile.getProfileId(), defaultProfile);
        for (CryptoFactory cryptoProfile : others) {
            profileMap.put(cryptoProfile.getProfileId(), cryptoProfile);
        }
    }
    
    @Override
    public CryptoFactory getDefault() {
        return defaultProfile;
    }

    @Override
    public CryptoFactory getFactory(int profileId) {
        return profileMap.get(profileId);
    }
    
    public static CryptoFactoryRegistry createBasicRegistry() {
        Security.addProvider(new BouncyCastleProvider());
        return new CryptoFactoryRegistryImpl(new CryptoFactoryImpl());
    }

}
