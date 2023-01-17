package amn;

import java.net.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

public class Client2 {
    // initialize socket and input output streams
    private Socket socket = null;
    private DataInputStream input = null;
    private DataOutputStream out = null;
    static Asymmetric asymmetric;
    static boolean keyPair;

    public Client2(String address, int port) throws Exception {
        // establish a connection
        socket = new Socket(address, port);
        System.out.println("Connected");
        OutputStream outputStream = socket.getOutputStream();
        // create an object output stream from the output stream so we can send an object through it
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
        // get the input stream from the connected socket
        InputStream inputStream = socket.getInputStream();
        // create a DataInputStream so we can read data from it.
        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
        // takes input from terminal
        input = new DataInputStream(System.in);
        // sends output to the socket
        out = new DataOutputStream(socket.getOutputStream());
        DataInputStream in = new DataInputStream(
                new BufferedInputStream(socket.getInputStream()));
        String signOutUser = "";
        String send = "";
        String rec = "";
        String pass = "";
        byte[] sig = new byte[512];
        String user = "";
        String sessionKey = "";
        String encryptSend = "";
        String currentLine = "";
        String state = "";
        byte[] sessionKeyBytes = new byte[16];
        try {
            out.writeUTF("Send Public");
            rec = in.readUTF();
            if (rec.equals("OKAY")) {
                System.out.println("recived!!!!!!!!!!!");
                //PublicKey publicKeyServer = (PublicKey) objectInputStream.readObject();
                Certificate certificate = (Certificate) objectInputStream.readObject();
                String publicServer = certificate.publicKey;
                Asymmetric asymmetric = new Asymmetric();
                PublicKey publicKeyServer = (PublicKey) asymmetric.loadPublicKey(publicServer);
                sessionKey = asymmetric.GenerateSessionKey(publicKeyServer);
                out.writeUTF(sessionKey);
                rec = in.readUTF();
                BufferedReader reader = new BufferedReader(new FileReader("keys/SessionKey"));
                currentLine = reader.readLine();
                reader.close();
                System.out.println("session " + currentLine);
                sessionKeyBytes = Base64.getDecoder().decode(currentLine);
                if (!rec.equals("Successful")) {
                    System.out.println("Closing connection");
                    // close the connection
                    input.close();
                    out.close();
                    socket.close();
                }
            }
            Decryption decryption = new Decryption();
            Encryption encryption = new Encryption();
            byte[] key = new byte[16];
            System.out.println("register");
            System.out.println("sign in");
            send = input.readLine();
            state = send;
            encryptSend = encryption.encryptAES(send, sessionKeyBytes);
            out.writeUTF(encryptSend);
            rec = in.readUTF();
            rec = decryption.decryptAES(rec, sessionKeyBytes);
            if (rec.equals("Enter Username: ")) {
                System.out.println(rec);
                send = input.readLine();
                signOutUser = send;
                user = send;
                encryptSend = encryption.encryptAES(send, sessionKeyBytes);
                out.writeUTF(encryptSend);
            }
            rec = in.readUTF();
            rec = decryption.decryptAES(rec, sessionKeyBytes);
            if (rec.equals("Enter Password: ")) {
                System.out.println(rec);
                send = input.readLine();
                pass = send;
                encryptSend = encryption.encryptAES(send, sessionKeyBytes);
                out.writeUTF(encryptSend);
            }
            if (state.equals("register")) {
                asymmetric = new Asymmetric();
                keyPair = asymmetric.RSAKeyPairGenerator(true, user);
                System.out.println("done generating key");
                objectOutputStream.writeObject(asymmetric.getPublicKey());
                rec = in.readUTF();
                rec = decryption.decryptAES(rec, sessionKeyBytes);
                System.out.println(rec);
                //rec registration complete

            } else {
                rec = in.readUTF();
                key = Files.readAllBytes(Paths.get("keys/symmetric"));
                rec = decryption.decryptAES(rec, key);
                System.out.println(rec);
            }
            if (rec.equals("Welcome!")) {
                Scanner reader = new Scanner(System.in);
                System.out.println("To add name type add");
                System.out.println("To get all your information type get");
                System.out.println("To search by name type search");
                System.out.println("To edit name type edit");
                System.out.println("To delete name type delete");
                System.out.println("To share row type share");
                System.out.println("To see requests type see");
                BufferedReader read = new BufferedReader(new FileReader("keys/RSAPrivate'" + user + "'"));
                currentLine = read.readLine();
                read.close();
                Key clientKey = asymmetric.loadPrivateKey(currentLine);
                PrivateKey privateClientKey = (PrivateKey) clientKey;
                //get add ...
                send = input.readLine();
                encryptSend = encryption.encryptAES(send, key);
                sig = asymmetric.Create_Digital_Signature(send, privateClientKey);
                SignatureObject signatureObject = new SignatureObject(encryptSend, sig);
                objectOutputStream.writeObject(signatureObject);
                if (send.equals("see")) {
                    List<String> reqs = new ArrayList<>();
                    rec = in.readUTF();
                    rec = decryption.decryptAES(rec, key);
                    System.out.println(rec);
                    if (!rec.equals("no requests")) {
                        read = new BufferedReader(new FileReader("keys/RSAPrivate'" + user + "'"));
                        currentLine = read.readLine();
                        read.close();
                        PrivateKey pk = (PrivateKey) asymmetric.loadPrivateKey(currentLine);
                        int cnt = 0;
                        while (!rec.equals("done!")) {
                            rec = in.readUTF();
                            if (cnt != 2) {
                                rec = asymmetric.DecryptRSA(rec, pk);
                            }
                            cnt++;
                            reqs.add(rec);
                            System.out.println(rec);
                            if (rec.equals("accept?")) {
                                cnt=0;
                                //accept
                                send = input.readLine();
                                encryptSend = encryption.encryptAES(send, key);
                                out.writeUTF(encryptSend);
                                if (send.equals("accept")) {
                                    System.out.println("size " + reqs.size());
                                    for (int i = 0; i < reqs.size(); i++) {
                                        encryptSend = encryption.encryptAES(reqs.get(i), key);
                                        out.writeUTF(encryptSend);
                                    }
                                    reqs.clear();
                                    rec = in.readUTF();
                                    rec = decryption.decryptAES(rec, key);
                                    System.out.println(rec);
                                }

                            }
                        }
                    }
                }
                if (send.equals("share")) {
                    //select client
                    rec = in.readUTF();
                    rec = decryption.decryptAES(rec, key);
                    System.out.println(rec);
                    if (rec.equals("Enter client's username ")) {
                        //username
                        send = input.readLine();
                        encryptSend = encryption.encryptAES(send, key);
                        out.writeUTF(encryptSend);
                        //public key
                        rec = in.readUTF();
                        rec = decryption.decryptAES(rec, key);
                        PublicKey publicKeyOtherClient = (PublicKey) asymmetric.loadPublicKey(rec);
                        //enter Name
                        rec = in.readUTF();
                        rec = decryption.decryptAES(rec, key);
                        System.out.println(rec);
                        send = input.readLine();
                        encryptSend = encryption.encryptAES(send, key);
                        out.writeUTF(encryptSend);
                        List<Message> listOfMessages = (List<Message>) objectInputStream.readObject();
                        String name = decryption.decryptAES(listOfMessages.get(1).getText(), key);
                        String email = decryption.decryptAES(listOfMessages.get(2).getText(), key);
                        String password = decryption.decryptAES(listOfMessages.get(3).getText(), key);
                        String description = decryption.decryptAES(listOfMessages.get(4).getText(), key);
                        String file = decryption.decryptAES(listOfMessages.get(5).getText(), key);
                        name = asymmetric.EncryptRSA(name, publicKeyOtherClient);
                        email = asymmetric.EncryptRSA(email, publicKeyOtherClient);
                        description = asymmetric.EncryptRSA(description, publicKeyOtherClient);
                        file = asymmetric.EncryptRSA(file, publicKeyOtherClient);
                        List<SignatureObject> info = new ArrayList<>();
                        info.add(new SignatureObject(name, sig));
                        info.add(new SignatureObject(email, sig));
                        info.add(new SignatureObject(password, sig));
                        info.add(new SignatureObject(description, sig));
                        info.add(new SignatureObject(file, sig));
                        objectOutputStream.writeObject(info);
                        System.out.println("Your request has been processed");

                    }

                }
                if (send.equals("get")) {
                    List<Message> listOfMessages = (List<Message>) objectInputStream.readObject();
                    System.out.println("All messages:");
                    for (int i = 0; i < listOfMessages.size(); i++) {
                        System.out.println(decryption.decryptAES(listOfMessages.get(i).getText(), key));
                    }
                }
                if (send.equals("add")) {
                    rec = in.readUTF();
                    rec = decryption.decryptAES(rec, key);
                    System.out.println(rec);
                    //name
                    send = input.readLine();
                    encryptSend = encryption.encryptAES(send, key);
                    out.writeUTF(encryptSend);
                    rec = in.readUTF();
                    rec = decryption.decryptAES(rec, key);
                    System.out.println(rec);
                    //Email
                    send = input.readLine();
                    encryptSend = encryption.encryptAES(send, key);
                    out.writeUTF(encryptSend);
                    rec = in.readUTF();
                    rec = decryption.decryptAES(rec, key);
                    System.out.println(rec);
                    //password
                    send = input.readLine();
                    read = new BufferedReader(new FileReader("keys/RSAPublic'" + user + "'"));
                    currentLine = read.readLine();
                    read.close();
                    clientKey = asymmetric.loadPublicKey(currentLine);
                    PublicKey publicClientKey = (PublicKey) clientKey;
                    //encryptSend = encryption.encryptAES(send, key);
                    encryptSend = asymmetric.EncryptRSA(send, publicClientKey);
                    out.writeUTF(encryptSend);
                    rec = in.readUTF();
                    rec = decryption.decryptAES(rec, key);
                    System.out.println(rec);
                    //des
                    send = input.readLine();
                    encryptSend = encryption.encryptAES(send, key);
                    out.writeUTF(encryptSend);
                    rec = in.readUTF();
                    rec = decryption.decryptAES(rec, key);
                    System.out.println(rec);
                    //files
                    send = input.readLine();
                    encryptSend = encryption.encryptAES(send, key);
                    out.writeUTF(encryptSend);
                    List<Message> listOfMessages = (List<Message>) objectInputStream.readObject();
                    // print out the text of every message
                    System.out.println("All messages:");
                    for (int i = 0; i < listOfMessages.size(); i++) {
                        System.out.println(decryption.decryptAES(listOfMessages.get(i).getText(), key));
                    }
                }
                if (send.equals("search") || send.equals("delete")) {
                    rec = in.readUTF();
                    rec = decryption.decryptAES(rec, key);
                    System.out.println(rec);
                    send = input.readLine();
                    encryptSend = encryption.encryptAES(send, key);
                    out.writeUTF(encryptSend);
                    List<Message> listOfMessages = (List<Message>) objectInputStream.readObject();
                    // print out the text of every message
                    System.out.println("All messages:");
                    for (int i = 0; i < listOfMessages.size(); i++) {
                        System.out.println(decryption.decryptAES(listOfMessages.get(i).getText(), key));
                    }
                    //listOfMessages.forEach((msg) -> System.out.println(msg.getText()));

                }
                if (send.equals("edit")) {
                    input = new DataInputStream(System.in);
                    // sends output to the socket
                    out = new DataOutputStream(socket.getOutputStream());
                    in = new DataInputStream(
                            new BufferedInputStream(socket.getInputStream()));
                    String rec1 = "";
                    rec1 = in.readUTF();
                    rec1 = decryption.decryptAES(rec1, key);
                    System.out.println(rec1);
                    send = input.readLine();
                    encryptSend = encryption.encryptAES(send, key);
                    out.writeUTF(encryptSend);
                    rec = in.readUTF();
                    rec = decryption.decryptAES(rec, key);
                    System.out.println(rec);
                    send = input.readLine();
                    encryptSend = encryption.encryptAES(send, key);
                    out.writeUTF(encryptSend);
                    List<Message> listOfMessages = (List<Message>) objectInputStream.readObject();
                    // print out the text of every message
                    System.out.println("All messages:");
                    for (int i = 0; i < listOfMessages.size(); i++) {
                        System.out.println(decryption.decryptAES(listOfMessages.get(i).getText(), key));
                    }
                }
                Server server = new Server();
                server.changeSignedIn(signOutUser, "no");
            }


        } catch (IOException | ClassNotFoundException i) {
            System.out.println(i);
        }
        if (rec.equals("Over")) {
            // string to read message from input
            System.out.println();
            System.out.println("Closing connection");

            // close the connection
            input.close();
            out.close();
            socket.close();
        }

    }

    public static void main(String[] args) throws Exception {
        Client client = new Client("127.0.0.1", 5000);
    }
}