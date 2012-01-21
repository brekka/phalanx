package org.brekka.phalanx.services;

import java.io.OutputStream;

import org.brekka.phalanx.model.SymmetricInfo;

public interface SymmetricEncryptor {

    /**
     * The thing to write the bytes to
     * @return
     */
    OutputStream encrypt(OutputStream os);
    
    /**
     * 
     * @return
     */
    SymmetricInfo complete();
}