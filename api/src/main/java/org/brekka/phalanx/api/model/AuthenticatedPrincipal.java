package org.brekka.phalanx.api.model;

public interface AuthenticatedPrincipal {

    Principal getPrincipal();
    
    PrivateKeyToken getDefaultPrivateKey();
}
