package org.brekka.phalanx.crypto;

public interface CryptoFactoryRegistry {

    CryptoFactory getDefault();
    
    CryptoFactory getFactory(int profileId);
}
