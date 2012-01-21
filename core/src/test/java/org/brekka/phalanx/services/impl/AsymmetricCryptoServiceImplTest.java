package org.brekka.phalanx.services.impl;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Random;
import java.util.UUID;

import net.iharder.Base64;

import org.brekka.phalanx.dao.AsymmetricKeyPairDAO;
import org.brekka.phalanx.dao.CryptoDataDAO;
import org.brekka.phalanx.model.AsymedCryptoData;
import org.brekka.phalanx.model.AsymmetricKeyPair;
import org.brekka.phalanx.model.IdentifiableEntity;
import org.brekka.phalanx.model.Principal;
import org.brekka.phalanx.model.PrivateKeyToken;
import org.brekka.phalanx.profile.CryptoProfileRegistry;
import org.brekka.phalanx.profile.impl.CryptoProfileRegistryImpl;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class AsymmetricCryptoServiceImplTest {

    private AsymmetricCryptoServiceImpl service;
    
    private PasswordBasedCryptoServiceImpl pbeService;
    
    private SymmetricCryptoServiceImpl symService;
    
    @Before
    public void setUp() throws Exception {
        CryptoProfileRegistry cryptoProfileRegistry = CryptoProfileRegistryImpl.createBasicRegistry();
        CryptoDataDAO cryptoDAO = new TestCryptoDataDAO();
        AsymmetricKeyPairDAO asymmetricKeyPairDAO = Mockito.mock(AsymmetricKeyPairDAO.class);
        
        symService = new SymmetricCryptoServiceImpl();
        symService.setCryptoDataDAO(cryptoDAO);
        symService.setCryptoProfileRegistry(cryptoProfileRegistry);
        
        pbeService = new PasswordBasedCryptoServiceImpl();
        pbeService.setCryptoDataDAO(cryptoDAO);
        pbeService.setCryptoProfileRegistry(cryptoProfileRegistry);
        
        service = new AsymmetricCryptoServiceImpl();
        service.setCryptoProfileRegistry(cryptoProfileRegistry);
        service.setCryptoDataDAO(cryptoDAO);
        service.setAsymetricKeyPairDAO(asymmetricKeyPairDAO);
        service.setPasswordBasedCryptoService(pbeService);
        service.setSymmetricCryptoService(symService);
    }

    @Test
    public void test() {
        byte[] data = new byte[58];
        new Random().nextBytes(data);
        String password = "password";
        Principal user = new Principal();
        AsymmetricKeyPair asyncKeyPair = service.generateKeyPair(password, user);
        assignIds(asyncKeyPair, asyncKeyPair.getPrivateKey(), asyncKeyPair.getPublicKey());
        
        // Extract the private Key from what was created
        PrivateKeyToken privateKeyToken = service.decrypt(asyncKeyPair, password);
        
        AsymedCryptoData asyncCryptoData = service.encrypt(data, asyncKeyPair);
        byte[] result = service.decrypt(asyncCryptoData, privateKeyToken, byte[].class);
        System.out.printf("Data(%d): %s%n", asyncCryptoData.getData().length, Base64.encodeBytes(asyncCryptoData.getData()));
        assertTrue(Arrays.equals(data, result));
    }
    
    private void assignIds(IdentifiableEntity... entity) {
        for (IdentifiableEntity identifiableEntity : entity) {
            identifiableEntity.setId(UUID.randomUUID());
        }
    }

}
