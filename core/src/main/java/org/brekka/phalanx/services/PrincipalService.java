package org.brekka.phalanx.services;

import java.util.UUID;

import org.brekka.phalanx.model.AuthenticatedPrincipal;
import org.brekka.phalanx.model.Principal;

public interface PrincipalService {

    Principal createPrincipal(String password);
    
    AuthenticatedPrincipal authenticate(Principal user, String password);

    Principal retrieveById(UUID principalId);

    void deletePrincipal(UUID principalId);
}
