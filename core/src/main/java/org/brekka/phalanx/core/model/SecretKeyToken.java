package org.brekka.phalanx.core.model;

public interface SecretKeyToken {
    
    /**
     * The thing this secret key unlocks
     * @return
     */
    SymedCryptoData getSymedCryptoData();
}
