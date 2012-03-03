package org.brekka.phalanx.core.services;

import org.brekka.phalanx.core.model.PasswordedCryptoData;

public interface PasswordBasedCryptoService {

    <T> T decrypt(PasswordedCryptoData cryptoData, String password, Class<T> expectedType);
    
    PasswordedCryptoData encrypt(Object data, String password);
}
