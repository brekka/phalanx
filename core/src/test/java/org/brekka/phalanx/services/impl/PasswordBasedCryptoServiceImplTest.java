package org.brekka.phalanx.services.impl;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import org.brekka.phalanx.api.PhalanxException;
import org.brekka.phalanx.core.dao.CryptoDataDAO;
import org.brekka.phalanx.core.model.PasswordedCryptoData;
import org.brekka.phalanx.core.services.impl.PasswordBasedCryptoServiceImpl;
import org.brekka.phoenix.core.services.impl.CryptoProfileServiceImpl;
import org.brekka.xml.phoenix.v2.model.CryptoProfileRegistryDocument;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class PasswordBasedCryptoServiceImplTest {

    private PasswordBasedCryptoServiceImpl service;

    @Before
    public void setUp() throws Exception {
        CryptoProfileRegistryDocument regDoc = CryptoProfileRegistryDocument.Factory.parse(
                PasswordBasedCryptoServiceImpl.class.getClassLoader().getResourceAsStream(
                        "BasicCryptoProfileRegistry.xml"));
        CryptoProfileServiceImpl cryptoProfileService = new CryptoProfileServiceImpl(regDoc.getCryptoProfileRegistry());
        service = new PasswordBasedCryptoServiceImpl();
        CryptoDataDAO cryptoDAO = new TestCryptoDataDAO();
        service.setCryptoDataDAO(cryptoDAO);
        service.setCryptoProfileService(cryptoProfileService);
    }

    @Test @Ignore
    public void test() {
        byte[] data = new byte[58];
        new Random().nextBytes(data);
        PasswordedCryptoData encrypt = service.encrypt(data, "password");
        System.out.printf("Data(%d): %s%n",
                encrypt.getData().length, Base64.getEncoder().encodeToString(encrypt.getData()));

        System.out.printf("Salt(%d): %s%n",
                encrypt.getSalt().length, Base64.getEncoder().encodeToString(encrypt.getSalt()));

        long start = System.nanoTime();
        byte[] decrypted = service.decrypt(encrypt, "password", byte[].class);
        long end = System.nanoTime();

        System.out.printf("%.2f seconds%n", (float) (end - start) / 1000000000);
        assertTrue(Arrays.equals(data, decrypted));
    }

    @Test(expected=PhalanxException.class) @Ignore
    public void testInvalidPassword() {
        byte[] data = new byte[58];
        new Random().nextBytes(data);
        PasswordedCryptoData encrypt = service.encrypt(data, "password");
        System.out.printf("Data(%d): %s%n",
                encrypt.getData().length, Base64.getEncoder().encodeToString(encrypt.getData()));

        System.out.printf("Salt(%d): %s%n",
                encrypt.getSalt().length, Base64.getEncoder().encodeToString(encrypt.getSalt()));

        service.decrypt(encrypt, "notthepassword", byte[].class);
    }

}
