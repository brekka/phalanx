package org.brekka.phalanx.services;

import org.brekka.phalanx.model.AuthenticatedPrincipal;
import org.brekka.phalanx.model.PrivateKeyToken;

public interface PhalanxSessionService {

    byte[] registerPrivateKey(PrivateKeyToken defaultPrivateKey);

    PrivateKeyToken retrievePrivateKey(byte[] id);
    
    byte[] allocateAndBind(AuthenticatedPrincipal authenticatedPrincipal);

    void bind(byte[] sessionId);

    void unbind();

    AuthenticatedPrincipal getCurrentPrincipal();


}