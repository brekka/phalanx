package org.brekka.phalanx.services;

import org.brekka.phalanx.model.AuthenticatedPrincipal;
import org.brekka.phalanx.model.Principal;

public interface PrincipalService {

    Principal createPrincipal(String password);
    
    AuthenticatedPrincipal authenticate(Principal user, String password);
}
