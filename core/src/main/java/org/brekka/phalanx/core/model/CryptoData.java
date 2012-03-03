package org.brekka.phalanx.core.model;

import javax.persistence.Column;
import javax.persistence.DiscriminatorColumn;
import javax.persistence.DiscriminatorType;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.Table;

/**
 * The implementation describes the mechanism used to encrypt the payload data, not the data itself which could be anything.
 * 
 * @author Andrew Taylor
 */
@Entity
@Inheritance(strategy=InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name="Type", discriminatorType=DiscriminatorType.STRING, length=8)
@Table(name="\"CryptoData\"")
@DiscriminatorValue("Plain")
public class CryptoData extends IdentifiableEntity {
    
    /**
     * Serial UID
     */
    private static final long serialVersionUID = 118372503696946797L;

    @Column(name="Data", nullable=false)
    private byte[] data;
    
    @Column(name="Profile")
    private int profile;

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public int getProfile() {
        return profile;
    }

    public void setProfile(int profile) {
        this.profile = profile;
    }
}
