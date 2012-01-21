package org.brekka.phalanx.model;

import java.sql.Blob;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name="\"Content\"")
public class Content extends IdentifiableEntity {

    @Column(name="Data")
    private Blob data;

    public Blob getData() {
        return data;
    }

    public void setData(Blob data) {
        this.data = data;
    }
}
