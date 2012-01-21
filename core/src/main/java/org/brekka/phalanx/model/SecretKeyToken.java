package org.brekka.phalanx.model;

public interface SecretKeyToken {
    
    /**
     * The thing this secret key unlocks
     * @return
     */
    SymedCryptoData getSymedCryptoData();
}
