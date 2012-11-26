package org.brekka.phalanx.core.services.impl;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.UUID;

import org.brekka.phalanx.api.PhalanxErrorCode;
import org.brekka.phalanx.api.PhalanxException;
import org.brekka.phalanx.core.model.SymedCryptoData;
import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.PrivateKey;
import org.brekka.phoenix.api.SecretKey;
import org.brekka.phoenix.api.services.AsymmetricCryptoService;
import org.brekka.phoenix.api.services.CryptoProfileService;
import org.brekka.phoenix.api.services.DerivedKeyCryptoService;
import org.brekka.phoenix.api.services.DigestCryptoService;
import org.brekka.phoenix.api.services.SymmetricCryptoService;
import org.springframework.beans.factory.annotation.Autowired;

public abstract class AbstractCryptoService {
    private static final byte[] PK_MAGIC_MARKER = "IPKT".getBytes();
    private static final byte[] SK_MAGIC_MARKER = "ISKT".getBytes();

    
    @Autowired
    protected CryptoProfileService cryptoProfileService;
    
    @Autowired
    protected AsymmetricCryptoService phoenixAsymmetric;
    
    @Autowired
    protected SymmetricCryptoService phoenixSymmetric;
    
    @Autowired
    protected DerivedKeyCryptoService phoenixDerived;
    
    @Autowired
    protected DigestCryptoService phoenixDigest;
    
    @SuppressWarnings("unchecked")
    protected <T> T toType(byte[] data, Class<T> expectedType, UUID idOfData, CryptoProfile cryptoProfile) {
        if (expectedType == null) {
            throw new NullPointerException("An expected type is required");
        }
        Object retVal;
        if (expectedType.isArray() 
                && expectedType.getComponentType() == Byte.TYPE) {
            retVal = data;
        } else if (expectedType == InternalPrivateKeyToken.class) {
            retVal = decodePrivateKey(data, idOfData, cryptoProfile);
        } else if (expectedType == InternalSecretKeyToken.class) {
            retVal = decodeSecretKey(data, idOfData);
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
        CryptoProfile cryptoProfile = cryptoProfileService.retrieveProfile(profileId);
        byte[] data = new byte[encoded.length - (SK_MAGIC_MARKER.length + 20)];
        buffer.get(data);
        
        SecretKey secretKey = phoenixSymmetric.toSecretKey(data, cryptoProfile);
        SymedCryptoData symedCryptoData = new SymedCryptoData();
        symedCryptoData.setId(symCryptoDataId);
        symedCryptoData.setProfile(profileId);
        return new InternalSecretKeyToken(secretKey, symedCryptoData);
    }
    

    
    private InternalPrivateKeyToken decodePrivateKey(byte[] encoded, UUID idOfData, CryptoProfile cryptoProfile) {
        ByteBuffer buffer = ByteBuffer.wrap(encoded);
        byte[] marker = new byte[PK_MAGIC_MARKER.length];
        buffer.get(marker);
        if (!Arrays.equals(PK_MAGIC_MARKER, marker)) {
            throw new PhalanxException(PhalanxErrorCode.CP208, 
                    "CryptoData item '%s' does not appear to contain a private key", idOfData);
        }
        int profileId = buffer.getInt();
        CryptoProfile profile = cryptoProfileService.retrieveProfile(profileId);
        byte[] data = new byte[encoded.length - (SK_MAGIC_MARKER.length + 4)];
        buffer.get(data);
        
        PrivateKey privateKey = phoenixAsymmetric.toPrivateKey(data, profile);
        return new InternalPrivateKeyToken(privateKey);
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
    
    private static byte[] encodeSecretKey(InternalSecretKeyToken iskt) {
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

    private static byte[] encodePrivateKey(InternalPrivateKeyToken pkt) {
        int profileId = pkt.getKeyPair().getPrivateKey().getProfile();
        byte[] data = pkt.getPrivateKey().getEncoded();
        ByteBuffer buffer = ByteBuffer.allocate(PK_MAGIC_MARKER.length + 4 + data.length)
                .put(PK_MAGIC_MARKER)
                .putInt(profileId)
                .put(data);
        return buffer.array();
    }
}
