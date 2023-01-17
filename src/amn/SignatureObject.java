package amn;

import java.io.Serializable;

public class SignatureObject implements Serializable{
    private String message;
    private byte[] sig;
    public SignatureObject (String message , byte[] sig){
        this.message = message;
        this.sig = sig;
    }
    public String getMessage() {
        return message;
    }
    public byte[] getSig() {
        return sig;
    }
}
