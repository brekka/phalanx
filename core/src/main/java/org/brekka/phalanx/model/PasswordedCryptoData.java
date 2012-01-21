package org.brekka.phalanx.model;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

/**
 * A piece of content that has been encypted using a password based encryption scheme.
 * 
 * @author Andrew Taylor
 */
@Entity
@DiscriminatorValue("Password")
public class PasswordedCryptoData extends CryptoData {
    
    @Column(name="Salt")
    private byte[] salt;

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }
}
