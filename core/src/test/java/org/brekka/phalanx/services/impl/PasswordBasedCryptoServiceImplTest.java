package org.brekka.phalanx.services.impl;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Random;

import net.iharder.Base64;

import org.brekka.phalanx.api.PhalanxException;
import org.brekka.phalanx.core.dao.CryptoDataDAO;
import org.brekka.phalanx.core.model.PasswordedCryptoData;
import org.brekka.phalanx.core.services.impl.PasswordBasedCryptoServiceImpl;
import org.brekka.phoenix.config.CryptoFactoryRegistry;
import org.brekka.phoenix.config.impl.CryptoFactoryRegistryImpl;
import org.brekka.xml.phoenix.v1.model.CryptoProfileRegistryDocument;
import org.junit.Before;
import org.junit.Test;

public class PasswordBasedCryptoServiceImplTest {

    private PasswordBasedCryptoServiceImpl service;
    
    @Before
    public void setUp() throws Exception {
        CryptoProfileRegistryDocument regDoc = CryptoProfileRegistryDocument.Factory.parse(
                PasswordBasedCryptoServiceImpl.class.getClassLoader().getResourceAsStream(
                        "BasicCryptoProfileRegistry.xml"));
        CryptoFactoryRegistry cryptoProfileRegistry = CryptoFactoryRegistryImpl.createRegistry(regDoc.getCryptoProfileRegistry());
        service = new PasswordBasedCryptoServiceImpl();
        CryptoDataDAO cryptoDAO = new TestCryptoDataDAO();
        service.setCryptoDataDAO(cryptoDAO);
        service.setCryptoProfileRegistry(cryptoProfileRegistry);
    }

    @Test
    public void test() {
        byte[] data = new byte[58];
        new Random().nextBytes(data);
        PasswordedCryptoData encrypt = service.encrypt(data, "password");
        System.out.printf("Data(%d): %s%n", encrypt.getData().length, Base64.encodeBytes(encrypt.getData()));
        System.out.printf("Salt(%d): %s%n", encrypt.getSalt().length, Base64.encodeBytes(encrypt.getSalt()));
        long start = System.nanoTime();
        byte[] decrypted = service.decrypt(encrypt, "password", byte[].class);
        long end = System.nanoTime();
        
        System.out.printf("%.2f seconds%n", (float) (end - start) / 1000000000);
        assertTrue(Arrays.equals(data, decrypted));
    }
    
    @Test(expected=PhalanxException.class)
    public void testInvalidPassword() {
        byte[] data = new byte[58];
        new Random().nextBytes(data);
        PasswordedCryptoData encrypt = service.encrypt(data, "password");
        System.out.printf("Data(%d): %s%n", encrypt.getData().length, Base64.encodeBytes(encrypt.getData()));
        System.out.printf("Salt(%d): %s%n", encrypt.getSalt().length, Base64.encodeBytes(encrypt.getSalt()));
        service.decrypt(encrypt, "notthepassword", byte[].class);
    }

}
