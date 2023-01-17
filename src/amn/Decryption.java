package amn;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
public class Decryption {
    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/CBC/PKCS5Padding";
    private static final String IV = "encryptionIntVec";
    private static final String HMAC_SHA512 = "HmacSHA512";
    public static String calculateHMAC(byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac sha512Hmac = Mac.getInstance(HMAC_SHA512);
        SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_SHA512);
        sha512Hmac.init(keySpec);
        byte[] macData = sha512Hmac.doFinal("My message".getBytes(StandardCharsets.UTF_8));
        String result = Base64.getEncoder().encodeToString(macData);
        return result;
    }
    public String decryptAES(String value , byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        String mac = calculateHMAC(key);
        if(mac.equals(Files.readAllLines(Paths.get("keys/lengthWithoutHmac")))){
            System.out.println("yayyyy");
        }
        byte [] values = Base64.getDecoder().decode(value);
        IvParameterSpec iv =new IvParameterSpec(IV.getBytes());
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(MODE);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
        return new String(cipher.doFinal(values));
    }
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException {
        Decryption decryption = new Decryption();
        String dec = decryption.decryptAES("lG8vTq28FFRN7PYqKGmuxg==" , "1234kaCieeLwWywZ".getBytes(StandardCharsets.UTF_8));
        System.out.println(dec);
    }
}

