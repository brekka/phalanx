package org.brekka.phalanx.services.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlOptions;
import org.brekka.phalanx.PhalanxErrorCode;
import org.brekka.phalanx.PhalanxException;
import org.brekka.phalanx.crypto.CryptoFactory;
import org.brekka.phalanx.crypto.CryptoFactoryRegistry;
import org.brekka.phalanx.model.SymedCryptoData;
import org.springframework.beans.factory.annotation.Autowired;

public abstract class AbstractCryptoService {
    private static final byte[] PK_MAGIC_MARKER = "IPKT".getBytes();
    private static final byte[] SK_MAGIC_MARKER = "ISKT".getBytes();

    @Autowired
    private CryptoFactoryRegistry cryptoProfileRegistry;
    
    private XmlOptions xmlOptions = new XmlOptions();

    @SuppressWarnings("unchecked")
    protected <T> T toType(byte[] data, Class<T> expectedType, UUID idOfData, CryptoFactory cryptoProfile) {
        if (expectedType == null) {
            throw new NullPointerException("An expected type is required");
        }
        Object retVal;
        if (expectedType.isArray() 
                && expectedType.getComponentType() == Byte.TYPE) {
            retVal = data;
        } else if (expectedType == PublicKey.class) {
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(data);
            try {
                KeyFactory keyFactory = cryptoProfile.getAsymmetric().getKeyFactory();
                retVal = keyFactory.generatePublic(publicKeySpec);
            } catch (InvalidKeySpecException e) {
                throw new PhalanxException(PhalanxErrorCode.CP200, e, 
                        "Failed to extract public key from CryptoData item '%s'", idOfData);
            }
        } else if (expectedType == InternalPrivateKeyToken.class) {
            retVal = decodePrivateKey(data, idOfData);
        } else if (expectedType == InternalSecretKeyToken.class) {
            retVal = decodeSecretKey(data, idOfData);
        } else if (XmlObject.class.isAssignableFrom(expectedType)) {
            retVal = decodeXmlObject(data, idOfData);
        } else {
            throw new IllegalArgumentException(String.format(
                    "Unsupport type conversion to '%s'", expectedType.getName()));
        }
        return (T) retVal;
    }

    protected byte[] toBytes(Object obj) {
        byte[] retVal;
        if (obj == null) {
            throw new NullPointerException("An object to encrypt must be specified");
        }
        Class<?> clazz = obj.getClass();
        if (clazz.isArray() && clazz.getComponentType() == Byte.TYPE) {
            retVal = (byte[]) obj;
        } else if (obj instanceof InternalPrivateKeyToken) {
            InternalPrivateKeyToken pkt = (InternalPrivateKeyToken) obj;
            retVal = encodePrivateKey(pkt);
        } else if (obj instanceof InternalSecretKeyToken) {
            InternalSecretKeyToken iskt = (InternalSecretKeyToken) obj;
            retVal = encodeSecretKey(iskt);
        } else if (obj instanceof Key) {
            retVal = ((Key) obj).getEncoded();
        } else if (obj instanceof XmlObject) {
            retVal = encodeXmlObject((XmlObject) obj);
        } else {
            throw new IllegalArgumentException(String.format("Unsupport type conversion from '%s'", clazz.getName()));
        }
        return retVal;
    }

    private InternalSecretKeyToken decodeSecretKey(byte[] encoded, UUID idOfData) {
        ByteBuffer buffer = ByteBuffer.wrap(encoded);
        byte[] marker = new byte[SK_MAGIC_MARKER.length];
        buffer.get(marker);
        if (!Arrays.equals(SK_MAGIC_MARKER, marker)) {
            throw new PhalanxException(PhalanxErrorCode.CP213, 
                    "CryptoData item '%s' does not appear to contain a secret key", idOfData);
        }
        int profileId = buffer.getInt();
        byte[] keyId = new byte[16];
        buffer.get(keyId);
        UUID symCryptoDataId = toUUID(keyId);
        CryptoFactory cryptoProfile = getCryptoProfileRegistry().getFactory(profileId);
        byte[] data = new byte[encoded.length - (SK_MAGIC_MARKER.length + 20)];
        buffer.get(data);
        SecretKey secretKey = new SecretKeySpec(data, cryptoProfile.getSymmetric().getKeyGenerator().getAlgorithm());
        SymedCryptoData symedCryptoData = new SymedCryptoData();
        symedCryptoData.setId(symCryptoDataId);
        symedCryptoData.setProfile(profileId);
        return new InternalSecretKeyToken(secretKey, symedCryptoData);
    }
    
    private byte[] encodeSecretKey(InternalSecretKeyToken iskt) {
        int profileId = iskt.getSymedCryptoData().getProfile();
        byte[] keyId = toBytes(iskt.getSymedCryptoData().getId());
        byte[] data = iskt.getSecretKey().getEncoded();
        ByteBuffer buffer = ByteBuffer.allocate(SK_MAGIC_MARKER.length + 20 + data.length)
                .put(SK_MAGIC_MARKER)
                .putInt(profileId)
                .put(keyId)
                .put(data);
        return buffer.array();
    }

    private byte[] encodePrivateKey(InternalPrivateKeyToken pkt) {
        int profileId = pkt.getKeyPair().getPrivateKey().getProfile();
        byte[] data = pkt.getPrivateKey().getEncoded();
        ByteBuffer buffer = ByteBuffer.allocate(PK_MAGIC_MARKER.length + 4 + data.length)
                .put(PK_MAGIC_MARKER)
                .putInt(profileId)
                .put(data);
        return buffer.array();
    }
    
    private InternalPrivateKeyToken decodePrivateKey(byte[] encoded, UUID idOfData) {
        ByteBuffer buffer = ByteBuffer.wrap(encoded);
        byte[] marker = new byte[PK_MAGIC_MARKER.length];
        buffer.get(marker);
        if (!Arrays.equals(PK_MAGIC_MARKER, marker)) {
            throw new PhalanxException(PhalanxErrorCode.CP208, 
                    "CryptoData item '%s' does not appear to contain a private key", idOfData);
        }
        int profileId = buffer.getInt();
        CryptoFactory cryptoProfile = getCryptoProfileRegistry().getFactory(profileId);
        byte[] data = new byte[encoded.length - (SK_MAGIC_MARKER.length + 4)];
        buffer.get(data);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(data);
        try {
            KeyFactory keyFactory = cryptoProfile.getAsymmetric().getKeyFactory();
            PrivateKey privateKey =  keyFactory.generatePrivate(privateKeySpec);
            return new InternalPrivateKeyToken(privateKey);
        } catch (InvalidKeySpecException e) {
            throw new PhalanxException(PhalanxErrorCode.CP207, e, 
                    "Failed to extract private key from CryptoData item '%s'", idOfData);
        }
    }
    
    
    private byte[] encodeXmlObject(XmlObject obj) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        try {
            obj.save(baos, xmlOptions);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return baos.toByteArray();
    }
    
    private XmlObject decodeXmlObject(byte[] data, UUID idOfData) {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        XmlObject obj;
        try {
            obj = XmlObject.Factory.parse(bais);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (XmlException e) {
            // TODO
            throw new IllegalStateException(e);
        }
        return obj;
    }

    protected final CryptoFactoryRegistry getCryptoProfileRegistry() {
        return cryptoProfileRegistry;
    }

    public void setCryptoProfileRegistry(CryptoFactoryRegistry cryptoProfileRegistry) {
        this.cryptoProfileRegistry = cryptoProfileRegistry;
    }


    /**
     * From http://stackoverflow.com/questions/772802/storing-uuid-as-base64-string.
     * @param uuid
     * @return
     */
    public static byte[] toBytes(UUID uuid) {
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        byte[] buffer = new byte[16];
        for (int i = 0; i < 8; i++) {
            buffer[i] = (byte) (msb >>> 8 * (7 - i));
        }
        for (int i = 8; i < 16; i++) {
            buffer[i] = (byte) (lsb >>> 8 * (7 - i));
        }
        return buffer;
    }

    /**
     * From private {@link UUID} constructor
     * @param data
     * @return
     */
    public static UUID toUUID(byte[] data) {
        long msb = 0;
        long lsb = 0;
        assert data.length == 16 : "data must be 16 bytes in length";
        for (int i = 0; i < 8; i++) {
            msb = (msb << 8) | (data[i] & 0xff);
        }
        for (int i = 8; i < 16; i++) {
            lsb = (lsb << 8) | (data[i] & 0xff);
        }
        UUID result = new UUID(msb, lsb);
        return result;
    }
}
