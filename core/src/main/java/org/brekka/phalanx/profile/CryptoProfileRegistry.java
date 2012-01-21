package org.brekka.phalanx.profile;

public interface CryptoProfileRegistry {

    CryptoProfile getDefaultProfile();
    
    CryptoProfile getProfile(int profileId);
}
