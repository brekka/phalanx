package org.brekka.phalanx.api.model;

import java.util.UUID;

public interface Principal {
    
    UUID getId();

    KeyPair getDefaultKeyPair();

}