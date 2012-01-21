package org.brekka.phalanx.services;

import org.brekka.phalanx.model.PasswordedCryptoData;

public interface PasswordBasedCryptoService {

    <T> T decrypt(PasswordedCryptoData cryptoData, String password, Class<T> expectedType);
    
    PasswordedCryptoData encrypt(Object data, String password);
}
