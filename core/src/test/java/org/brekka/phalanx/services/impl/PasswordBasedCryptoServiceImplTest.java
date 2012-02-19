package org.brekka.phalanx.services.impl;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Random;

import net.iharder.Base64;

import org.brekka.phalanx.crypto.CryptoFactoryRegistry;
import org.brekka.phalanx.crypto.impl.CryptoFactoryRegistryImpl;
import org.brekka.phalanx.dao.CryptoDataDAO;
import org.brekka.phalanx.model.PasswordedCryptoData;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.core.io.ClassPathResource;

public class PasswordBasedCryptoServiceImplTest {

    private PasswordBasedCryptoServiceImpl service;
    
    @Before
    public void setUp() throws Exception {
        CryptoFactoryRegistry cryptoProfileRegistry = CryptoFactoryRegistryImpl.createBasicRegistryFromXml(
                new ClassPathResource("BasicCryptoProfileRegistry.xml", PasswordBasedCryptoServiceImpl.class.getClassLoader()));
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

}
