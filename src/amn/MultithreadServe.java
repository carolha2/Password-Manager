package amn;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MultithreadServe implements Runnable {
    private Socket socket;
    private DataInputStream input = null;
    private DataOutputStream out = null;
    static Asymmetric asymmetric;
    static boolean keyPair;

    public MultithreadServe(Socket socket) {
        this.socket = socket;
    }

    public void writeToFile(String path, byte[] key) throws IOException, IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f, true);
        String lineSeparator = System.getProperty("line.separator");
        fos.write(key);
        fos.write(lineSeparator.getBytes());
        fos.flush();
        fos.close();
    }

    static Certificate certificate;

    public void run() {
        System.out.println("Connected: " + socket);
        try {
            InputStream inputStream = socket.getInputStream();
            // create a DataInputStream so we can read data from it.
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
            // get the output stream from the socket.
            OutputStream outputStream = socket.getOutputStream();
            // create an object output stream from the output stream so we can send an object through it
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
            //input from client
            DataInputStream in = new DataInputStream(
                    new BufferedInputStream(socket.getInputStream()));
            // takes input from terminal
            input = new DataInputStream(System.in);
            // sends output to the socket
            out = new DataOutputStream(socket.getOutputStream());
            String send = "";
            String rec = "";
            String user = "";
            String pass = "";
            String sessionKey = "";
            String encryptedPass = "";
            boolean signature = true;
            SignatureObject signatureObject;
            Server server = new Server();
            try {
                rec = in.readUTF();
                System.out.println(rec);
                if (rec.equals("Send Public")) {
                    while (!keyPair) {
                        wait();
                    }
                    send = "OKAY";
                    out.writeUTF(send);
                    //objectOutputStream.writeObject(asymmetric.getPublicKey());
                    objectOutputStream.writeObject(certificate);
                    rec = in.readUTF();
                    sessionKey = asymmetric.DecryptRSA(rec, asymmetric.getPrivateKey());
                    BufferedReader reader = new BufferedReader(new FileReader("keys/SessionKey"));
                    String currentLine = reader.readLine();
                    reader.close();
                    if (!sessionKey.equals(currentLine)) {
                        System.out.println("Closing connection");
                        // close connection
                        socket.close();
                        in.close();
                    } else {
                        send = "Successful";
                        out.writeUTF(send);
                    }
                }
                Encryption encryption = new Encryption();
                Decryption decryption = new Decryption();
                byte[] sessionKeyBytes = Base64.getDecoder().decode(sessionKey);
                rec = in.readUTF();
                rec = decryption.decryptAES(rec, sessionKeyBytes);
                System.out.println(rec);
                if (rec.equals("register") || rec.equals("sign in")) {
                    send = "Enter Username: ";
                    send = encryption.encryptAES(send, sessionKeyBytes);
                    out.writeUTF(send);
                    user = in.readUTF();
                    user = decryption.decryptAES(user, sessionKeyBytes);
                    System.out.println(user);
                    send = "Enter Password: ";
                    send = encryption.encryptAES(send, sessionKeyBytes);
                    out.writeUTF(send);
                    pass = in.readUTF();
                    pass = decryption.decryptAES(pass, sessionKeyBytes);
                    System.out.println(pass);
                    if (rec.equals("register")) {
                        PublicKey publicKeyClient = (PublicKey) objectInputStream.readObject();
                        String publicKeyClientString = asymmetric.publicKeyToString(publicKeyClient);
                        BufferedReader reader = new BufferedReader(new FileReader("keys/DBPublic"));
                        String currentLine = reader.readLine();
                        reader.close();
                        Key encryptKey = asymmetric.loadPublicKey(currentLine);
                        encryptedPass = asymmetric.EncryptRSA(pass, (PublicKey) encryptKey);
                        if (server.RegisterClient(user, encryptedPass, publicKeyClientString)) {
                            send = "Registration complete!";
                            send = encryption.encryptAES(send, sessionKeyBytes);
                            out.writeUTF(send);
                        }
                    } else if (rec.equals("sign in")) {
                        boolean signed = false;
                        String getEncryptedPass = "";
                        BufferedReader reader = new BufferedReader(new FileReader("keys/DBPrivate"));
                        String currentLine = reader.readLine();
                        reader.close();
                        getEncryptedPass = server.GetPass(user);
                        Key encryptKey = asymmetric.loadPrivateKey(currentLine);
                        encryptedPass = asymmetric.DecryptRSA(getEncryptedPass, (PrivateKey) encryptKey);
                        System.out.println("encryptedPass " + encryptedPass);
                        if (encryptedPass.equals(pass)) {
                            System.out.println("YAAAAAAAAAAAY");
                            server.changeSignedIn(user, "yes");
                            signed = true;

                        }
                        if (signed == true) {
                            send = "Welcome!";
                            byte[] key = encryption.KeyGen(pass);
                            send = encryption.encryptAES(send, key);
                            SignedIn signedIn = new SignedIn();
                            List<Message> messages = new ArrayList<>();
                            out.writeUTF(send);
                            //get add ...
                            signatureObject = (SignatureObject) objectInputStream.readObject();
                            String command = decryption.decryptAES(signatureObject.getMessage(), key);
                            System.out.println(command);
                            byte result[] = signatureObject.getSig();
                            String publicKeyClientString = server.GetPublicKey(user);
                            Key publicKeyClientKey = asymmetric.loadPublicKey(publicKeyClientString);
                            PublicKey publicKeyClient = (PublicKey) publicKeyClientKey;
                            signature = signature || asymmetric.Verify_Digital_Signature("get".getBytes(StandardCharsets.UTF_8), result, publicKeyClient);
                            signature = signature || asymmetric.Verify_Digital_Signature("add".getBytes(StandardCharsets.UTF_8), result, publicKeyClient);
                            signature = signature || asymmetric.Verify_Digital_Signature("search".getBytes(StandardCharsets.UTF_8), result, publicKeyClient);
                            signature = signature || asymmetric.Verify_Digital_Signature("edit".getBytes(StandardCharsets.UTF_8), result, publicKeyClient);
                            signature = signature || asymmetric.Verify_Digital_Signature("delete".getBytes(StandardCharsets.UTF_8), result, publicKeyClient);
                            signature = signature || asymmetric.Verify_Digital_Signature("share".getBytes(StandardCharsets.UTF_8), result, publicKeyClient);
                            signature = signature || asymmetric.Verify_Digital_Signature("see".getBytes(StandardCharsets.UTF_8), result, publicKeyClient);
                            System.out.println("sig " + signature);
                            if (!signature) {
                                System.out.println("Closing connection");
                                // close connection
                                socket.close();
                                in.close();
                            }
                            switch (command) {
                                case "see":
                                    Path path = Paths.get("keys/requests'" + user + "'");
                                    if (path.toFile().isFile()) {
                                        send = "you have requests";
                                        send = encryption.encryptAES(send, key);
                                        out.writeUTF(send);
                                        File file = new File("keys/requests'" + user + "'");
                                        BufferedReader br = new BufferedReader(new FileReader(file));
                                        String st;
                                        int cnt = 0;
                                        while ((st = br.readLine()) != null) {
                                            System.out.println("cnt " + cnt);
                                            if (cnt < 4) {
                                                cnt++;
                                                out.writeUTF(st);
                                            } else {
                                                out.writeUTF(st);
                                                send = "accept?";
                                                String clientpb = server.GetPublicKey(user);
                                                PublicKey pb = (PublicKey) asymmetric.loadPublicKey(clientpb);
                                                send = asymmetric.EncryptRSA(send, pb);
                                                out.writeUTF(send);
                                                rec = in.readUTF();
                                                rec = decryption.decryptAES(rec, key);
                                                if (rec.equals("accept")) {
                                                    rec = in.readUTF();
                                                    String name = decryption.decryptAES(rec, key);
                                                    rec = in.readUTF();
                                                    String email = decryption.decryptAES(rec, key);
                                                    rec = in.readUTF();
                                                    String password = decryption.decryptAES(rec, key);
                                                    rec = in.readUTF();
                                                    String des = decryption.decryptAES(rec, key);
                                                    rec = in.readUTF();
                                                    String files = decryption.decryptAES(rec, key);
                                                    rec = in.readUTF();
                                                    String username = decryption.decryptAES(rec, key);
                                                    signedIn.Add(name, email, password, des, files, user);
                                                    send = "accepted";
                                                    send = encryption.encryptAES(send, key);
                                                    out.writeUTF(send);
                                                }

                                            }
                                        }
                                        br.close();
                                        send = "done!";
                                        String clientpb = server.GetPublicKey(user);
                                        PublicKey pb = (PublicKey) asymmetric.loadPublicKey(clientpb);
                                        send = asymmetric.EncryptRSA(send, pb);
                                        out.writeUTF(send);
                                        Files.deleteIfExists(Paths.get("keys/requests'" + user + "'"));
                                    } else {
                                        send = "no requests";
                                        send = encryption.encryptAES(send, key);
                                        out.writeUTF(send);
                                    }
                                    break;
                                case "share":
                                    send = "Enter client's username ";
                                    send = encryption.encryptAES(send, key);
                                    out.writeUTF(send);
                                    //username
                                    rec = in.readUTF();
                                    String clientUser = decryption.decryptAES(rec, key);
                                    System.out.println(clientUser);
                                    String clientpb = server.GetPublicKey(clientUser);
                                    send = encryption.encryptAES(clientpb, key);
                                    out.writeUTF(send);
                                    send = "enter name";
                                    send = encryption.encryptAES(send, key);
                                    out.writeUTF(send);
                                    //name
                                    rec = in.readUTF();
                                    rec = decryption.decryptAES(rec, key);
                                    System.out.println(rec);
                                    messages = signedIn.SearchByName(user, rec);
                                    System.out.println("Sending messages to the ClientSocket");
                                    for (int i = 0; i < messages.size(); i++) {
                                        objectOutputStream.writeObject(messages);
                                    }
                                    List<SignatureObject> info = (List<SignatureObject>) objectInputStream.readObject();
                                    for (int i = 0; i < info.size(); i++) {
                                        writeToFile("keys/requests'" + clientUser + "'", info.get(i).getMessage().getBytes(StandardCharsets.UTF_8));
                                    }
                                    break;
                                case "get":
                                    messages = signedIn.GetAll(user);
                                    System.out.println("Sending messages to the ClientSocket");
                                    for (int i = 0; i < messages.size(); i++) {
                                        objectOutputStream.writeObject(messages);
                                    }
                                    break;
                                case "add":
                                    send = "Enter name: ";
                                    send = encryption.encryptAES(send, key);
                                    out.writeUTF(send);
                                    rec = in.readUTF();
                                    String name = decryption.decryptAES(rec, key);
                                    send = "Enter Email: ";
                                    send = encryption.encryptAES(send, key);
                                    out.writeUTF(send);
                                    rec = in.readUTF();
                                    String email = decryption.decryptAES(rec, key);
                                    send = "Enter password: ";
                                    send = encryption.encryptAES(send, key);
                                    out.writeUTF(send);
                                    rec = in.readUTF();
                                    //String password = decryption.decryptAES(rec, key);
                                    String password = rec;
                                    send = "Enter description: ";
                                    send = encryption.encryptAES(send, key);
                                    out.writeUTF(send);
                                    rec = in.readUTF();
                                    String des = decryption.decryptAES(rec, key);
                                    send = "Enter files: ";
                                    send = encryption.encryptAES(send, key);
                                    out.writeUTF(send);
                                    rec = in.readUTF();
                                    String files = decryption.decryptAES(rec, key);
                                    signedIn.Add(name, email, password, des, files, user);
                                    messages = signedIn.GetAll(user);
                                    System.out.println("Sending messages to the ClientSocket");
                                    for (int i = 0; i < messages.size(); i++) {
                                        objectOutputStream.writeObject(messages);
                                    }
                                    break;
                                case "search":
                                    send = "Enter name: ";
                                    send = encryption.encryptAES(send, key);
                                    out.writeUTF(send);
                                    rec = in.readUTF();
                                    rec = decryption.decryptAES(rec, key);
                                    System.out.println(rec);
                                    messages = signedIn.SearchByName(user, rec);
                                    System.out.println("Sending messages to the ClientSocket");
                                    for (int i = 0; i < messages.size(); i++) {
                                        objectOutputStream.writeObject(messages);
                                    }
                                    break;
                                case "edit":
                                    input = new DataInputStream(System.in);
                                    // sends output to the socket
                                    out = new DataOutputStream(socket.getOutputStream());
                                    send = "Enter old name: ";
                                    send = encryption.encryptAES(send, key);
                                    System.out.println("send " + send);
                                    out.writeUTF(send);
                                    rec = in.readUTF();
                                    rec = decryption.decryptAES(rec, key);
                                    System.out.println(rec);
                                    String newName = "";
                                    send = "Enter new name: ";
                                    send = encryption.encryptAES(send, key);
                                    out.writeUTF(send);
                                    newName = in.readUTF();
                                    newName = decryption.decryptAES(newName, key);
                                    System.out.println(newName);
                                    signedIn.EditName(user, rec, newName);
                                    messages = signedIn.GetAll(user);
                                    System.out.println("Sending messages to the ClientSocket");
                                    for (int i = 0; i < messages.size(); i++) {
                                        objectOutputStream.writeObject(messages);
                                    }
                                    break;
                                case "delete":
                                    send = "Enter name: ";
                                    send = encryption.encryptAES(send, key);
                                    out.writeUTF(send);
                                    rec = in.readUTF();
                                    rec = decryption.decryptAES(rec, key);
                                    System.out.println(rec);
                                    signedIn.DeleteName(user, rec);
                                    messages = signedIn.GetAll(user);
                                    System.out.println("Sending messages to the ClientSocket");
                                    for (int i = 0; i < messages.size(); i++) {
                                        objectOutputStream.writeObject(messages);
                                    }
                                    break;
                                default:
                                    break;
                            }

                        }
                    }
                }


            } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException i) {
                System.out.println(i);
            } catch (SQLException throwables) {
                throwables.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }
            if (rec.equals("over")) {
                System.out.println("Closing connection");

                // close connection
                socket.close();
                in.close();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        asymmetric = new Asymmetric();
        keyPair = asymmetric.RSAKeyPairGenerator(false, "");
        System.out.println("keyPair");
        Encryption encryption = new Encryption();
        byte[] symKey = encryption.KeyGen("1234");
        File f = new File("keys/CA");
        f.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(symKey);
        fos.flush();
        fos.close();
        CSR csr = new CSR();
        csr = csr.createCSR(asymmetric.getPublicKey(), "PasswordManager.com", "PasswordManager", "Damascus", "Syria");
        Socket socket = null;
        DataInputStream input = null;
        DataOutputStream out = null;
        try {
            socket = new Socket("127.0.0.1", 3000);
            System.out.println("Connected");
            input = new DataInputStream(System.in);
            // sends output to the socket
            System.out.println("1");
            out = new DataOutputStream(socket.getOutputStream());
            System.out.println("1");
        } catch (UnknownHostException u) {
            System.out.println(u);
        } catch (IOException i) {
            System.out.println(i);
        }
        ObjectOutputStream os = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream is = new ObjectInputStream(socket.getInputStream());
        os.writeObject(csr);
        certificate = (Certificate) is.readObject();
        // close the connection
        try {
            input.close();
            out.close();
            socket.close();
        } catch (IOException i) {
            System.out.println(i);
        }
        try (ServerSocket listener = new ServerSocket(5000)) {
            System.out.println("Is running");
            ExecutorService pool = Executors.newFixedThreadPool(20);
            while (true) {
                pool.execute(new MultithreadServe(listener.accept()));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
