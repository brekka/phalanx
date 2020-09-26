package org.brekka.phalanx.api.model;


import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.util.Random;
import java.util.UUID;

import org.junit.Test;

public class ExportedPrincipalTest {

    @Test
    public void importExport() {
        Random random = new Random(7742L);
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        byte[] cipherText = new byte[16];
        random.nextBytes(cipherText);
        ExportedPrincipal principal = new ExportedPrincipal(101, UUID.randomUUID(), UUID.randomUUID(), iv, cipherText);
        byte[] asBytes = principal.toBytes();
        ExportedPrincipal restored = ExportedPrincipal.fromBytes(asBytes);
        assertThat(restored, equalTo(principal));
    }

    @Test(expected = IllegalArgumentException.class)
    public void ivTooBig() {
        Random random = new Random(7742L);
        byte[] iv = new byte[100];
        random.nextBytes(iv);
        byte[] cipherText = new byte[16];
        random.nextBytes(cipherText);
        new ExportedPrincipal(101, UUID.randomUUID(), UUID.randomUUID(), iv, cipherText);
    }

    @Test(expected = IllegalArgumentException.class)
    public void cipherTextTooBig() {
        byte[] iv = new byte[16];
        byte[] cipherText = new byte[129];
        new ExportedPrincipal(101, UUID.randomUUID(), UUID.randomUUID(), iv, cipherText);
    }

}
