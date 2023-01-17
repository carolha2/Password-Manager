package amn;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;

public class GetCertificate {
    private Socket socket            = null;
    private DataInputStream input   = null;
    private DataOutputStream out     = null;

    // constructor to put ip address and port
    public GetCertificate(String address, int port)
    {

    }

    public static void main(String args[])
    {
        //Client client = new Client("127.0.0.1", 5000);
    }
}
