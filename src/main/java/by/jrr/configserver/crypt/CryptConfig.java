package by.jrr.configserver.crypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

public class CryptConfig {

    public void config() {
        Security.addProvider(new BouncyCastleProvider());

    }

    public SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = new SecureRandom();
        int keyBitSize = 256;
        keyGenerator.init(keyBitSize, secureRandom);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey;
    }

    public String encrypt(SecretKey secretKey, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        AlgorithmParameters parameters = cipher.getParameters();
        IvParameterSpec ivParameterSpec = parameters.getParameterSpec(IvParameterSpec.class);
        byte[] data = password.getBytes("UTF-8");
        byte[] cipherText = cipher.doFinal(data);
        byte[] iv = ivParameterSpec.getIV();
        return base64Encode(iv) + ":" + base64Encode(cipherText);
    }

    public String decrypt(SecretKey secretKey, String str) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        String iv = str.split(":")[0];
        String property = str.split(":")[1];
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(base64Decode(iv)));
        byte[] data = base64Decode(property);
        byte[] cipherText = cipher.doFinal(data);
        return new String(cipherText, "UTF-8");
    }

    private static String base64Encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] base64Decode(String property) throws IOException {
        return Base64.getDecoder().decode(property);
    }
}
//"ded3c851-2df5-4e4c-87cd-244bb15b82e1"