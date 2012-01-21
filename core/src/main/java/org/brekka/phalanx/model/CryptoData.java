package org.brekka.phalanx.model;

import javax.persistence.Column;
import javax.persistence.DiscriminatorColumn;
import javax.persistence.DiscriminatorType;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.Table;

@Entity
@Inheritance(strategy=InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name="Type", discriminatorType=DiscriminatorType.STRING, length=8)
@Table(name="\"CryptoData\"")
@DiscriminatorValue("Plain")
public class CryptoData extends IdentifiableEntity {
    
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
