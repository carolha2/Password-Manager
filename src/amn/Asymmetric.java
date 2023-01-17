package amn;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Asymmetric {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private static final String SIGNING_ALGORITHM = "SHA1withRSA";

    public void writeToFile(String path, byte[] key) throws IOException, IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        String lineSeparator = System.getProperty("line.separator");
        fos.write(key);
        fos.write(lineSeparator.getBytes());
        fos.flush();
        fos.close();
    }
    public String readFromFile(String path) throws IOException {
        BufferedReader read = new BufferedReader(new FileReader(path));
        String currentLine = read.readLine();
        read.close();
        return currentLine;
    }

    public Boolean RSAKeyPairGenerator(boolean client, String clientName) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(4096);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
        String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        if (client == false) {
            writeToFile("keys/RSAPublic", publicKeyString.getBytes(StandardCharsets.UTF_8));
            writeToFile("keys/RSAPrivate", privateKeyString.getBytes(StandardCharsets.UTF_8));
        } else {
            writeToFile("keys/RSAPublic'" + clientName + "'", publicKeyString.getBytes(StandardCharsets.UTF_8));
            writeToFile("keys/RSAPrivate'" + clientName + "'", privateKeyString.getBytes(StandardCharsets.UTF_8));
            //writeToFile("keys/RSAClientPublic", publicKeyString.getBytes(StandardCharsets.UTF_8));
            //writeToFile("keys/RSAClientPrivate", privateKeyString.getBytes(StandardCharsets.UTF_8));
        }
        return true;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public static String EncryptRSA(String plainText, PublicKey publicKey) throws Exception {
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");
        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        //Perform Encryption
        byte[] cipherText = cipher.doFinal(plainText.getBytes());
        String s = Base64.getEncoder().encodeToString(cipherText);
        return s;
    }

    public static byte[] Create_Digital_Signature(String input, PrivateKey key) throws Exception {
        Signature rsa = Signature.getInstance(SIGNING_ALGORITHM);
        rsa.initSign(key);
        rsa.update(input.getBytes());
        return rsa.sign();
    }
    public static boolean Verify_Digital_Signature(byte[] input, byte[] signatureToVerify, PublicKey key) throws Exception
    {
        Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
        signature.initVerify(key);
        signature.update(input);
        return signature.verify(signatureToVerify);
    }
    public static String DecryptRSA(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] cipherTextArray = Base64.getDecoder().decode(cipherText);
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");
        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        //Perform Decryption
        byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);
        return new String(decryptedTextArray);
    }

    public String GenerateSessionKey(PublicKey publicKey) throws Exception {
        SecretKeySpec secretKey;
        SecureRandom rnd = new SecureRandom();
        byte[] key = new byte[16];
        rnd.nextBytes(key);
        secretKey = new SecretKeySpec(key, "AES");
        String s = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        writeToFile("keys/SessionKey", s.getBytes(StandardCharsets.UTF_8));
        return EncryptRSA(s, publicKey);
    }

    public String publicKeyToString(PublicKey publicKey) {
        byte[] publicKeyByte = publicKey.getEncoded();
        String publicKeyString = Base64.getEncoder().encodeToString(publicKeyByte);
        System.out.println(publicKeyString);
        return publicKeyString;
    }

    public static Key loadPublicKey(String storedPublic) {
        try {
            byte[] data = Base64.getDecoder().decode(storedPublic.getBytes());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            return fact.generatePublic(spec);

        } catch (Exception ignored) {
        }
        return null;
    }

    public static Key loadPrivateKey(String storedPrivate) {
        try {
            byte[] data = Base64.getDecoder().decode(storedPrivate.getBytes());
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            return fact.generatePrivate(spec);

        } catch (Exception ignored) {
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        Asymmetric asymmetric = new Asymmetric();
        Boolean keyPair = asymmetric.RSAKeyPairGenerator(false , "");
        String data = "get";
        byte[] sig = Create_Digital_Signature(data , asymmetric.privateKey);
        boolean carol = Verify_Digital_Signature(data.getBytes(StandardCharsets.UTF_8),sig, asymmetric.getPublicKey());
        System.out.println(carol);
    }


}
