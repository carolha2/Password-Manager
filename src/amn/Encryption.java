package amn;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.Random;

import com.github.netricecake.hkdf.HKDF;
import org.bouncycastle.openpgp.*;

import static com.sun.org.apache.bcel.internal.classfile.Utility.toHexString;

public class Encryption {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/CBC/PKCS5Padding";
    private static final String IV = "encryptionIntVec";
    private static final String HMAC_SHA512 = "HmacSHA512";
    protected  static byte[] KEY = new byte[16];
    protected byte[] KeyGen(String password) throws IOException {
        boolean isUpperCase;
        int randomNumber;
        Random randomNumberGenerator = new Random();
        int limit = 16 - password.length();
        for (int i = 0; i < limit; i++) {
            isUpperCase = randomNumberGenerator.nextBoolean();
            randomNumber = randomNumberGenerator.nextInt(26) + 65;
            password += isUpperCase ? (char) randomNumber :
                    Character.toLowerCase((char) randomNumber);
        }
        File f = new File("keys/symmetric");
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(password.getBytes(StandardCharsets.UTF_8));
        fos.flush();
        fos.close();
        return password.getBytes(StandardCharsets.UTF_8);
    }
    public byte[] keygen (String pass){
        while(pass.length() < 16)
            pass+="E";
        return pass.getBytes(StandardCharsets.UTF_8);
    }
    public static String calculateHMAC(byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac sha512Hmac = Mac.getInstance(HMAC_SHA512);
        SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_SHA512);
        sha512Hmac.init(keySpec);
        byte[] macData = sha512Hmac.doFinal("My message".getBytes(StandardCharsets.UTF_8));
        String result = Base64.getEncoder().encodeToString(macData);
        return result;
    }

    public static void WriteMac(byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        String mac = calculateHMAC(key);
        File f = new File("keys/lengthWithoutHmac");
        FileOutputStream fos = new FileOutputStream(f, true);
            f.getParentFile().mkdirs();
            fos = new FileOutputStream(f);
            fos.write(mac.getBytes(StandardCharsets.UTF_8));
            fos.flush();
            fos.close();

    }
    public static String encryptAES(String value, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        KEY = key;
        WriteMac(KEY);
        IvParameterSpec iv = new IvParameterSpec(IV.getBytes());
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, ALGORITHM);
        Cipher cipher = Cipher.getInstance(MODE);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
        byte[] values = cipher.doFinal(value.getBytes());
        String s = Base64.getEncoder().encodeToString(values);
        return s;
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, SignatureException, IOException {
        Encryption encryption = new Encryption();
        byte[] key = encryption.KeyGen("12345");
        System.out.println(key);
        byte[] byteKey= Files.readAllBytes(Paths.get("keys/symmetric"));
        String en = encryption.encryptAES("Welcome!", key );
        System.out.println("en: " + en);
        Decryption decryption = new Decryption();
        String de = decryption.decryptAES(en, byteKey);
        System.out.println(de);


    }
}
