package org.brekka.phalanx.core.services;

import java.util.UUID;

import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.core.model.Principal;

public interface PrincipalService {

    Principal createPrincipal(String password);
    
    AuthenticatedPrincipal authenticate(Principal user, String password);

    Principal retrieveById(UUID principalId);

    void deletePrincipal(UUID principalId);
}
