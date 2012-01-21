package org.brekka.phalanx.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;

@Entity
@Table(name = "\"User\"")
public class Principal extends IdentifiableEntity {

    /**
     * For DS members with certificates
     */
    @Column(name = "CertificateName")
    private String certificateName;

    /**
     * For regular customers.
     */
    @Column(name = "EMail")
    private String email;

    @OneToOne
    @JoinColumn(name = "DefaultKeyPair")
    private AsymmetricKeyPair defaultKeyPair;

    public String getCertificateName() {
        return certificateName;
    }

    public void setCertificateName(String certificateName) {
        this.certificateName = certificateName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public AsymmetricKeyPair getDefaultKeyPair() {
        return defaultKeyPair;
    }

    public void setDefaultKeyPair(AsymmetricKeyPair defaultKeyPair) {
        this.defaultKeyPair = defaultKeyPair;
    }

}
