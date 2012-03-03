package org.brekka.phalanx.core.services;

import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.api.model.PrivateKeyToken;

public interface PhalanxSessionService {

    byte[] registerPrivateKey(PrivateKeyToken defaultPrivateKey);

    PrivateKeyToken retrievePrivateKey(byte[] id);
    
    byte[] allocateAndBind(AuthenticatedPrincipal authenticatedPrincipal);

    void bind(byte[] sessionId);

    void unbind();

    AuthenticatedPrincipal getCurrentPrincipal();

    void logout(byte[] sessionID);
}