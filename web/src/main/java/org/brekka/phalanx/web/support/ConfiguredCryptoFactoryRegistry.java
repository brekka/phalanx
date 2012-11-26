package org.brekka.phalanx.web.support;

import org.brekka.phoenix.config.CryptoFactory;
import org.brekka.phoenix.config.CryptoFactoryRegistry;
import org.brekka.phoenix.config.impl.CryptoFactoryRegistryImpl;
import org.brekka.stillingar.api.annotations.ConfigurationListener;
import org.brekka.stillingar.api.annotations.Configured;
import org.brekka.xml.phoenix.v1.model.CryptoProfileRegistryDocument;
import org.brekka.xml.phoenix.v1.model.CryptoProfileRegistryDocument.CryptoProfileRegistry;
import org.springframework.stereotype.Component;

@Configured
@Component
public class ConfiguredCryptoFactoryRegistry implements CryptoFactoryRegistry {
    
    private CryptoFactoryRegistry delegate;
    
    @Override
    public CryptoFactory getDefault() {
        return delegate.getDefault();
    }
    
    @Override
    public CryptoFactory getFactory(int profileId) {
        return delegate.getFactory(profileId);
    }
    
    
    @ConfigurationListener
    public void configure(@Configured CryptoProfileRegistry cryptoProfileRegistry) {
        delegate = CryptoFactoryRegistryImpl.createRegistry(cryptoProfileRegistry);
    }
}
