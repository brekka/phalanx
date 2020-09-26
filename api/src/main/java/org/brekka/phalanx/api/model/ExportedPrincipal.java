/*
 * Copyright 2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.brekka.phalanx.api.model;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * An {@link AuthenticatedPrincipal} that has been exported using a separate encryption key.
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
public final class ExportedPrincipal implements Serializable {
    /**
     * Serial UID
     */
    private static final long serialVersionUID = 2120952772879347355L;

    private static final int MAX_IV_LENGTH = 32;          //  256 bits
    private static final int MAX_CIPHERTEXT_LENGTH = 128; // 1024 bits
    private static final int MAX_ENCODED_LENGTH = 4 + 16 + 16 + 1 + MAX_IV_LENGTH + 1 + MAX_CIPHERTEXT_LENGTH;

    private final int cryptoProfileId;

    private final UUID principalId;

    private final UUID symKeyId;

    private final byte[] iv;

    private final byte[] cipherText;

    public ExportedPrincipal(
            final int cryptoProfileId,
            final UUID principalId,
            final UUID symKeyId,
            final byte[] iv,
            final byte[] cipherText) {

        this.cryptoProfileId = cryptoProfileId;
        this.principalId = Objects.requireNonNull(principalId);
        this.symKeyId = Objects.requireNonNull(symKeyId);
        this.iv = Objects.requireNonNull(iv);
        if (iv.length > MAX_IV_LENGTH) {
            throw new IllegalArgumentException(String.format(
                    "IV length %d must be less than %d bytes", iv.length, MAX_IV_LENGTH));
        }
        this.cipherText = Objects.requireNonNull(cipherText);
        if (cipherText.length > MAX_CIPHERTEXT_LENGTH) {
            throw new IllegalArgumentException(String.format(
                "Cipher text length %d must be less than %d bytes", cipherText.length, MAX_CIPHERTEXT_LENGTH));
        }
    }


    public byte[] getIv() {
        return iv;
    }

    public int getCryptoProfileId() {
        return cryptoProfileId;
    }

    public UUID getPrincipalId() {
        return principalId;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public UUID getSymKeyId() {
        return symKeyId;
    }

    @Override
    public int hashCode() {
        return Objects.hash(cryptoProfileId, principalId, symKeyId, Arrays.hashCode(cipherText), Arrays.hashCode(iv));
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ExportedPrincipal other = (ExportedPrincipal) obj;
        return Objects.equals(cryptoProfileId, other.cryptoProfileId)
            && Objects.equals(principalId, other.principalId)
            && Objects.equals(symKeyId, other.symKeyId)
            && Arrays.equals(iv, other.iv)
            && Arrays.equals(cipherText, other.cipherText);
    }


    public byte[] toBytes() {
        ByteBuffer buf = ByteBuffer.allocate(MAX_ENCODED_LENGTH);
        buf.putInt(cryptoProfileId);
        buf.putLong(principalId.getMostSignificantBits());
        buf.putLong(principalId.getLeastSignificantBits());
        buf.putLong(symKeyId.getMostSignificantBits());
        buf.putLong(symKeyId.getLeastSignificantBits());
        buf.put((byte) iv.length);
        buf.put(iv);
        buf.put((byte) (cipherText.length & 0xFF));
        buf.put(cipherText);
        buf.flip();
        return Arrays.copyOf(buf.array(), buf.remaining());
    }

    public static ExportedPrincipal fromBytes(final byte[] data) {
        ByteBuffer buf = ByteBuffer.wrap(data);
        int cryptoProfileId = buf.getInt();
        UUID principalId = new UUID(buf.getLong(), buf.getLong());
        UUID symKeyId = new UUID(buf.getLong(), buf.getLong());
        int ivLength = buf.get();
        byte[] iv = new byte[ivLength];
        buf.get(iv);
        int cipherTextLength = (buf.get() & 0xFF);
        byte[] cipherText = new byte[cipherTextLength];
        buf.get(cipherText);
        return new ExportedPrincipal(cryptoProfileId, principalId, symKeyId, iv, cipherText);
    }
}
