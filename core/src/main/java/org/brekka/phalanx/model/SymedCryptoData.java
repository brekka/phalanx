package org.brekka.phalanx.model;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;

/**
 * A piece of data that is protected by a symmetric key and IV. For example this would normally be used
 * to protect a private key.
 * 
 * @author Andrew Taylor
 */
@Entity
@DiscriminatorValue("Sym")
public class SymedCryptoData extends CryptoData {

    /**
     * Serial UID
     */
    private static final long serialVersionUID = -1121467573145122568L;

    @Column(name="IV")
    private byte[] iv;
    
    /**
     * The thing that is protecting this data
     */
    @OneToOne
    @JoinColumn(name="KeyDataID")
    private CryptoData key;

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public CryptoData getKey() {
        return key;
    }

    public void setKey(CryptoData key) {
        this.key = key;
    }
}
