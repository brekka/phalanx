package org.brekka.phalanx.services.impl;

import org.brekka.phalanx.PhalanxErrorCode;
import org.brekka.phalanx.PhalanxException;
import org.brekka.phalanx.dao.PrincipalDAO;
import org.brekka.phalanx.model.AsymmetricKeyPair;
import org.brekka.phalanx.model.AuthenticatedPrincipal;
import org.brekka.phalanx.model.CryptoData;
import org.brekka.phalanx.model.PasswordedCryptoData;
import org.brekka.phalanx.model.Principal;
import org.brekka.phalanx.services.AsymmetricCryptoService;
import org.brekka.phalanx.services.PasswordBasedCryptoService;
import org.brekka.phalanx.services.PrincipalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class PrincipalServiceImpl implements PrincipalService {

    @Autowired
    private PrincipalDAO userDAO;
    
    @Autowired
    private PasswordBasedCryptoService passwordBasedCryptoService;
    
    @Autowired
    private AsymmetricCryptoService asymmetricCryptoService;
    
    @Override
    @Transactional(propagation=Propagation.SUPPORTS)
    public AuthenticatedPrincipal authenticate(Principal user, String password) {
        Principal managedUser = userDAO.retrieveById(user.getId());
        AsymmetricKeyPair defaultKeyPair = managedUser.getDefaultKeyPair();
        CryptoData privateKeyData = defaultKeyPair.getPrivateKey();
        InternalPrivateKeyToken privateKeyToken;
        if (privateKeyData instanceof PasswordedCryptoData) {
            PasswordedCryptoData passwordedData = (PasswordedCryptoData) privateKeyData;
            privateKeyToken = passwordBasedCryptoService.decrypt(passwordedData, password, InternalPrivateKeyToken.class);
            privateKeyToken.setAsymetricKeyPair(defaultKeyPair);
        } else {
            throw new PhalanxException(PhalanxErrorCode.CP202, 
                    "Unable to decrypt private key for user '%s'. Expected %s, found %s for id %s", 
                    user.getId(), PasswordedCryptoData.class.getSimpleName(), privateKeyData.getClass().getSimpleName(),
                    privateKeyData.getId());
        }
        InternalAuthenticatedUser authenticatedUser = new InternalAuthenticatedUser(managedUser, privateKeyToken);
        return authenticatedUser;
    }
    
    @Override
    @Transactional(propagation=Propagation.REQUIRED)
    public Principal createUser(String password) {
        Principal user = new Principal();
        AsymmetricKeyPair keyPair = asymmetricCryptoService.generateKeyPair(password, user);
        user.setDefaultKeyPair(keyPair);
        return user;
    }

}
