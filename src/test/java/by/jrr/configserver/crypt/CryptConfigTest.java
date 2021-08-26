package by.jrr.configserver.crypt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;

class CryptConfigTest {
    CryptConfig cryptConfig = new CryptConfig();

    @Test
    void test() throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
        SecretKey key = cryptConfig.generateSecretKey();
        String password = "ded3c851-2df5-4e4c-87cd-244bb15b82e1";
        String encrypt = cryptConfig.encrypt(key, password);
        System.out.println(encrypt);
        String decrypt = cryptConfig.decrypt(key, encrypt);
        System.out.println(decrypt);
        Assertions.assertEquals(password, decrypt);

    }

}