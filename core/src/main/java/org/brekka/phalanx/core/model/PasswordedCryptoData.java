package org.brekka.phalanx.core.model;

import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

import org.brekka.phalanx.api.model.CryptedData;

/**
 * A piece of content that has been encypted using a password based encryption scheme.
 * 
 * @author Andrew Taylor
 */
@Entity
@DiscriminatorValue("Password")
public class PasswordedCryptoData extends CryptoData implements CryptedData {
    
    /**
     * Serial UID
     */
    private static final long serialVersionUID = 7900986833181045388L;
    
    
    @Column(name="Salt")
    private byte[] salt;
    
    public PasswordedCryptoData() {
    }
    
    public PasswordedCryptoData(UUID id) {
        setId(id);
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }
}