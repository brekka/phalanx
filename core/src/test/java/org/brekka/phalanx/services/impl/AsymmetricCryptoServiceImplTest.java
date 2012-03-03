package org.brekka.phalanx.services.impl;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Random;

import net.iharder.Base64;

import org.brekka.phalanx.api.model.PrivateKeyToken;
import org.brekka.phalanx.core.dao.AsymmetricKeyPairDAO;
import org.brekka.phalanx.core.dao.CryptoDataDAO;
import org.brekka.phalanx.core.model.AsymedCryptoData;
import org.brekka.phalanx.core.model.AsymmetricKeyPair;
import org.brekka.phalanx.core.model.Principal;
import org.brekka.phalanx.core.services.impl.AsymmetricCryptoServiceImpl;
import org.brekka.phalanx.core.services.impl.PasswordBasedCryptoServiceImpl;
import org.brekka.phalanx.core.services.impl.SymmetricCryptoServiceImpl;
import org.brekka.phoenix.CryptoFactoryRegistry;
import org.brekka.phoenix.impl.CryptoFactoryRegistryImpl;
import org.brekka.xml.phoenix.v1.model.CryptoProfileRegistryDocument;
import org.junit.Before;
import org.junit.Test;

public class AsymmetricCryptoServiceImplTest {

    private AsymmetricCryptoServiceImpl service;
    
    private PasswordBasedCryptoServiceImpl pbeService;
    
    private SymmetricCryptoServiceImpl symService;
    
    @Before
    public void setUp() throws Exception {
        CryptoProfileRegistryDocument regDoc = CryptoProfileRegistryDocument.Factory.parse(
                PasswordBasedCryptoServiceImpl.class.getClassLoader().getResourceAsStream(
                        "BasicCryptoProfileRegistry.xml"));
        CryptoFactoryRegistry cryptoProfileRegistry = CryptoFactoryRegistryImpl.createRegistry(regDoc.getCryptoProfileRegistry());
        CryptoDataDAO cryptoDAO = new TestCryptoDataDAO();
        AsymmetricKeyPairDAO asymmetricKeyPairDAO = new TestAsymmetricKeyPairDAO();
        
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
        
        // Extract the private Key from what was created
        PrivateKeyToken privateKeyToken = service.decrypt(asyncKeyPair, password);
        
        AsymedCryptoData asyncCryptoData = service.encrypt(data, asyncKeyPair);
        byte[] result = service.decrypt(asyncCryptoData, privateKeyToken, byte[].class);
        System.out.printf("Data(%d): %s%n", asyncCryptoData.getData().length, Base64.encodeBytes(asyncCryptoData.getData()));
        assertTrue(Arrays.equals(data, result));
    }
    

}
