package org.brekka.phalanx.services.impl;

import org.brekka.phalanx.dao.PrincipalDAO;
import org.brekka.phalanx.model.AsymmetricKeyPair;
import org.brekka.phalanx.model.AuthenticatedPrincipal;
import org.brekka.phalanx.model.Principal;
import org.brekka.phalanx.services.AsymmetricCryptoService;
import org.brekka.phalanx.services.PrincipalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class PrincipalServiceImpl implements PrincipalService {

    @Autowired
    private PrincipalDAO principalDAO;
    
    @Autowired
    private AsymmetricCryptoService asymmetricCryptoService;
    
    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public AuthenticatedPrincipal authenticate(Principal principal, String password) {
        Principal managedUser = principalDAO.retrieveById(principal.getId());
        AsymmetricKeyPair defaultKeyPair = managedUser.getDefaultKeyPair();
        InternalPrivateKeyToken privateKeyToken = (InternalPrivateKeyToken) asymmetricCryptoService.decrypt(defaultKeyPair, password);
        InternalAuthenticatedUser authenticatedUser = new InternalAuthenticatedUser(managedUser, privateKeyToken);
        return authenticatedUser;
    }
    
    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public Principal createPrincipal(String password) {
        Principal principal = new Principal();
        AsymmetricKeyPair keyPair = asymmetricCryptoService.generateKeyPair(password, principal);
        principal.setDefaultKeyPair(keyPair);
        principalDAO.create(principal);
        return principal;
    }

}
