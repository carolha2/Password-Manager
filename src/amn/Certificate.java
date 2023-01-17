package amn;

import java.io.Serializable;

public class Certificate implements Serializable {
    String publicKey;
    String subject;
    String organizationName;
    String location, country;
    byte[] signature;

    public Certificate(String publicKey, String subject, String organizationName, String location, String country, byte[] sig) {
        this.publicKey = publicKey;
        this.subject = subject;
        this.organizationName = organizationName;
        this.location = location;
        this.country = country;
        this.signature = sig;

    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getSubject() {
        return subject;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public String getLocation() {
        return location;
    }

    public String getCountry() {
        return country;
    }

    public byte[] getSig() {
        return signature;
    }
}
