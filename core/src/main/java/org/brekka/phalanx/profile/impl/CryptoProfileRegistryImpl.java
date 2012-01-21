package org.brekka.phalanx.profile.impl;

import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.brekka.phalanx.profile.CryptoProfile;
import org.brekka.phalanx.profile.CryptoProfileRegistry;

public class CryptoProfileRegistryImpl implements CryptoProfileRegistry {

    private CryptoProfile defaultProfile;
    
    private Map<Integer, CryptoProfile> profileMap = new HashMap<>();
    
    public CryptoProfileRegistryImpl(CryptoProfile defaultProfile, CryptoProfile... others) {
        this.defaultProfile = defaultProfile;
        profileMap.put(defaultProfile.getId(), defaultProfile);
        for (CryptoProfile cryptoProfile : others) {
            profileMap.put(cryptoProfile.getId(), cryptoProfile);
        }
    }
    
    @Override
    public CryptoProfile getDefaultProfile() {
        return defaultProfile;
    }

    @Override
    public CryptoProfile getProfile(int profileId) {
        return profileMap.get(profileId);
    }
    
    public static CryptoProfileRegistry createBasicRegistry() {
        Security.addProvider(new BouncyCastleProvider());
        return new CryptoProfileRegistryImpl(new CryptoProfileImpl());
    }

}
