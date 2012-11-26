package org.brekka.phalanx.web.support;

import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.services.CryptoProfileService;
import org.brekka.phoenix.services.impl.CryptoProfileServiceImpl;
import org.brekka.stillingar.api.annotations.ConfigurationListener;
import org.brekka.stillingar.api.annotations.Configured;
import org.brekka.xml.phoenix.v2.model.CryptoProfileRegistryDocument.CryptoProfileRegistry;
import org.springframework.stereotype.Component;

@Configured
@Component
public class ConfiguredCryptoProfileService implements CryptoProfileService {
    
    private CryptoProfileService delegate;
    
    /**
     * @param profileNumber
     * @return
     * @see org.brekka.phoenix.api.services.CryptoProfileService#retrieveProfile(int)
     */
    public CryptoProfile retrieveProfile(int profileNumber) {
        return delegate.retrieveProfile(profileNumber);
    }

    /**
     * @return
     * @see org.brekka.phoenix.api.services.CryptoProfileService#retrieveDefault()
     */
    public CryptoProfile retrieveDefault() {
        return delegate.retrieveDefault();
    }


    @ConfigurationListener
    public void configure(@Configured CryptoProfileRegistry cryptoProfileRegistry) {
        delegate = new CryptoProfileServiceImpl(cryptoProfileRegistry);
    }
}
