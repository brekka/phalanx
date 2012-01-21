package org.brekka.phalanx.model;

public interface AuthenticatedPrincipal {

    Principal getPrincipal();
    
    PrivateKeyToken getDefaultPrivateKey();
}
