package org.brekka.phalanx.services;

import org.brekka.phalanx.model.SecretKeyToken;
import org.brekka.phalanx.model.SymedCryptoData;



public interface SymmetricCryptoService {

    <T> T decrypt(SymedCryptoData cryptoData, SecretKeyToken secretKey, Class<T> expectedType);
    
    SymedCryptoData encrypt(Object data, SecretKeyToken secretKey);
    
    SecretKeyToken generateSecretKey();
}
