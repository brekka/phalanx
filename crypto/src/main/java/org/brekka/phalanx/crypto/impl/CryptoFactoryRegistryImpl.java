package org.brekka.phalanx.crypto.impl;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.xmlbeans.XmlException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.brekka.phalanx.crypto.CryptoErrorCode;
import org.brekka.phalanx.crypto.CryptoException;
import org.brekka.phalanx.crypto.CryptoFactory;
import org.brekka.phalanx.crypto.CryptoFactoryRegistry;
import org.brekka.xml.v1.phalanx.CryptoProfileDocument.CryptoProfile;
import org.brekka.xml.v1.phalanx.CryptoProfileRegistryDocument;
import org.brekka.xml.v1.phalanx.CryptoProfileRegistryDocument.CryptoProfileRegistry;
import org.springframework.core.io.Resource;

public class CryptoFactoryRegistryImpl implements CryptoFactoryRegistry {

    private CryptoFactory defaultProfile;
    
    private Map<Integer, CryptoFactory> profileMap = new HashMap<>();
    
    public CryptoFactoryRegistryImpl(CryptoFactory defaultProfile, CryptoFactory... others) {
        this.defaultProfile = defaultProfile;
        profileMap.put(defaultProfile.getProfileId(), defaultProfile);
        for (CryptoFactory cryptoProfile : others) {
            profileMap.put(cryptoProfile.getProfileId(), cryptoProfile);
        }
    }
    
    @Override
    public CryptoFactory getDefault() {
        return defaultProfile;
    }

    @Override
    public CryptoFactory getFactory(int profileId) {
        return profileMap.get(profileId);
    }
    
    public static CryptoFactoryRegistry createBasicRegistryFromXml(Resource resource) {
        Security.addProvider(new BouncyCastleProvider());
        CryptoProfileRegistryDocument doc;
        try (InputStream is = resource.getInputStream()) {
            doc = CryptoProfileRegistryDocument.Factory.parse(is);
        } catch (XmlException | IOException e) {
            throw new CryptoException(CryptoErrorCode.CP800, e, 
                    "Failed to read basic registry from resource '%s'", resource);
        }
        
        CryptoFactory defaultFactory = null;
        
        CryptoProfileRegistry cryptoProfileRegistry = doc.getCryptoProfileRegistry();
        List<CryptoProfile> cryptoProfileList = cryptoProfileRegistry.getCryptoProfileList();
        List<CryptoFactory> cryptoFactories = new ArrayList<>(cryptoProfileList.size());
        for (CryptoProfile cryptoProfile : cryptoProfileList) {
            CryptoFactory factory = new CryptoFactoryImpl(cryptoProfile);
            if (cryptoProfile.getID() == cryptoProfileRegistry.getDefaultProfileID()) {
                defaultFactory = factory;
            } else {
                cryptoFactories.add(factory); 
            }
        }
        return new CryptoFactoryRegistryImpl(defaultFactory, cryptoFactories.toArray(new CryptoFactory[cryptoFactories.size()]));
    }

}
