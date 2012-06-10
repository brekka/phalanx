package org.brekka.phalanx.client.services.impl;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.brekka.phalanx.api.PhalanxErrorCode;
import org.brekka.phalanx.api.PhalanxException;
import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.api.model.CryptedData;
import org.brekka.phalanx.api.model.KeyPair;
import org.brekka.phalanx.api.model.Principal;
import org.brekka.phalanx.api.model.PrivateKeyToken;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
public class PhalanxServiceClientTest {

    @Autowired
    private PhalanxServiceClient client;
    
    @Before
    public void setUp() throws Exception {
        
    }
    

    @Test
    public void testCreatePrincipal() {
        String password = "Password";
        Principal principal = client.createPrincipal(password);
        AuthenticatedPrincipal authenticate = client.authenticate(principal, password);
        assertEquals(principal.getId(), authenticate.getPrincipal().getId());
        assertEquals(principal.getDefaultKeyPair().getId(), authenticate.getPrincipal().getDefaultKeyPair().getId());
    }

    @Test
    public void testAsymmetric() {
        String password = "Password";
        byte[] data = "ThisIsATest".getBytes();
        Principal principal = client.createPrincipal(password);
        AuthenticatedPrincipal authenticate = client.authenticate(principal, password);
        CryptedData cryptedData = client.asymEncrypt(data, authenticate.getPrincipal().getDefaultKeyPair());
        
        byte[] plain = client.asymDecrypt(cryptedData, authenticate.getDefaultPrivateKey());
        assertTrue(Arrays.equals(data, plain));
    }

    @Test
    public void testPasswordBased() {
        String password = "Password";
        byte[] data = "ThisIsATest".getBytes();
        CryptedData encryptedData = client.pbeEncrypt(data, password);
        byte[] plain = client.pbeDecrypt(encryptedData, password);
        assertTrue(Arrays.equals(data, plain));
    }
    
    @Test
    public void testPasswordBased2() {
        String password = "PasswordPassword";
        byte[] data = "ThisIsATest".getBytes();
        CryptedData encryptedData = client.pbeEncrypt(data, password);
        byte[] plain = client.pbeDecrypt(encryptedData, password);
        assertTrue(Arrays.equals(data, plain));
    }
    
    @Test
    public void testIncorrectPassword() {
        String password = "PasswordPassword";
        byte[] data = "ThisIsATest".getBytes();
        CryptedData encryptedData = client.pbeEncrypt(data, password);
        try {
            client.pbeDecrypt(encryptedData, "IncorrectPassword");
            fail();
        } catch (PhalanxException e) {
            if (e.getErrorCode() != PhalanxErrorCode.CP302) {
                fail();
            }
        }
    }

    @Test
    public void testKeyPair() {
        String password = "Password";
        Principal principal = client.createPrincipal(password);
        AuthenticatedPrincipal authenticate = client.authenticate(principal, password);
        
        KeyPair newKeyPair = client.generateKeyPair(principal.getDefaultKeyPair(), principal);
        PrivateKeyToken newPrivateKey = client.decryptKeyPair(newKeyPair, authenticate.getDefaultPrivateKey());
        
        // Test encrypt/decrypt with new keypair
        byte[] data = "ThisIsATest".getBytes();
        CryptedData cryptedData = client.asymEncrypt(data, newKeyPair);
        byte[] plain = client.asymDecrypt(cryptedData, newPrivateKey);
        assertTrue(Arrays.equals(data, plain));
        
        // Assign
        String anotherPassword = "Password2";
        Principal anotherPrincipal = client.createPrincipal(anotherPassword);
        KeyPair assignedKeyPair = client.assignKeyPair(newPrivateKey, anotherPrincipal);
        
        // Use the other users assigned private key to decrypt the data
        AuthenticatedPrincipal anotherAuthenticate = client.authenticate(anotherPrincipal, anotherPassword);
        PrivateKeyToken assignedPrivateKey = client.decryptKeyPair(assignedKeyPair, anotherAuthenticate.getDefaultPrivateKey());
        byte[] otherPlain = client.asymDecrypt(cryptedData, assignedPrivateKey);
        assertTrue(Arrays.equals(data, otherPlain));
    }

}
