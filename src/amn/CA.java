package amn;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class CA {
    private Socket socket;
    private ServerSocket server = null;
    private DataInputStream in = null;

    public CA(int port){
        try
        {
            Decryption decryption = new Decryption();
            server = new ServerSocket(port);
            System.out.println("Server started");
            System.out.println("Waiting for a client ...");
            socket = server.accept();
            System.out.println("Client accepted");
            InputStream inputStream = socket.getInputStream();
            System.out.println("2");
            ObjectOutputStream os = new ObjectOutputStream(socket.getOutputStream());
            System.out.println("1");
            ObjectInputStream is = new ObjectInputStream(socket.getInputStream());
            System.out.println("2");
            // reads message from client until "Over" is sent
            BufferedReader read = new BufferedReader(new FileReader("keys/CA"));
            String currentLine = read.readLine();
            //System.out.println("currentline "+currentLine);
            read.close();
            byte[] key = currentLine.getBytes(StandardCharsets.UTF_8);
            //csr
            CSR csr = (CSR)is.readObject();
            csr.publicKey = decryption.decryptAES(csr.publicKey , key);
            csr.subject = decryption.decryptAES(csr.subject , key);
            csr.organizationName = decryption.decryptAES(csr.organizationName , key);
            csr.location = decryption.decryptAES(csr.location , key);
            csr.country = decryption.decryptAES(csr.country , key);
            Asymmetric asymmetric = new Asymmetric();
            asymmetric.RSAKeyPairGenerator(true,"CA");
            byte[] sig = asymmetric.Create_Digital_Signature("CA", asymmetric.getPrivateKey());
            Certificate certificate = new Certificate(csr.publicKey,csr.subject,csr.organizationName,csr.location,csr.country,sig);
            os.writeObject(certificate);
            System.out.println("Closing connection");
            // close connection
            //socket.close();
            //in.close();
        }
        catch(IOException | ClassNotFoundException | NoSuchAlgorithmException i)
        {
            System.out.println(i);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        CA ca = new CA(3000);
    }
}