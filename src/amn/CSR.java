package amn;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

public class CSR implements Serializable {
    String publicKey;
    String subject;
    String organizationName;
    String location,country;
    public CSR createCSR(PublicKey publicKey, String subject , String organizationName,String location , String country) throws Exception {
        CSR csr = new CSR();
        Encryption encryption = new Encryption();
        Asymmetric asymmetric = new Asymmetric();
        String pubKey = asymmetric.publicKeyToString(publicKey);
        BufferedReader read = new BufferedReader(new FileReader("keys/CA"));
        String currentLine = read.readLine();
        read.close();
        byte[] key = currentLine.getBytes(StandardCharsets.UTF_8);
        pubKey = encryption.encryptAES(pubKey , key);
        csr.publicKey = pubKey;
        subject = encryption.encryptAES(subject , key);
        csr.subject = subject;
        organizationName = encryption.encryptAES(organizationName , key);
        csr.organizationName = organizationName;
        location = encryption.encryptAES(location , key);
        csr.location = location;
        country = encryption.encryptAES(country , key);
        csr.country = country;
        return csr;
    }


}