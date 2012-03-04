package org.brekka.phalanx.core.services;

import org.brekka.phalanx.core.model.SecretKeyToken;
import org.brekka.phalanx.core.model.SymedCryptoData;



public interface SymmetricCryptoService {

    <T> T decrypt(SymedCryptoData cryptoData, SecretKeyToken secretKey, Class<T> expectedType);
    
    SymedCryptoData encrypt(Object data, SecretKeyToken secretKey);
    
    SecretKeyToken generateSecretKey();
}