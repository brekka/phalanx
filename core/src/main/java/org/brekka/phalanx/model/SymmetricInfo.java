package org.brekka.phalanx.model;

public interface SymmetricInfo {
    int getProfileId();

    byte[] getKey();

    byte[] getIv();
}