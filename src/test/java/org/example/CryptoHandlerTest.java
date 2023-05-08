package org.example;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class CryptoHandlerTest {

    private SecretKey secretKey;
    private CryptoHandler cryptoHandler;
    @BeforeEach
    void setUp() {
        cryptoHandler = new CryptoHandler();
        secretKey = new SecretKeySpec("1234567890123456".getBytes(StandardCharsets.UTF_8), "AES");

    }
    @Test
    void encrypt() throws Exception {
        byte[] bytes = "Hello worldlopki".getBytes(StandardCharsets.UTF_8);
        String encryptedText = cryptoHandler.encrypt(new String(bytes, StandardCharsets.UTF_8), secretKey);
        System.out.println(encryptedText);
        assertNotNull(encryptedText);
        assertNotEquals(0, encryptedText.length());
    }

    @Test
    void decrypt() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        byte[] data = "haslo".getBytes(StandardCharsets.UTF_8);
        String enc = cryptoHandler.encrypt(new String(data, StandardCharsets.UTF_8), secretKey);
        String dec = cryptoHandler.decrypt(enc, secretKey);
        System.out.println(dec);
        assertNotNull(enc);
        assertEquals("haslo", dec);
    }

    @Test
    void decrypt1() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        byte[] data = "asd".getBytes(StandardCharsets.UTF_8);
        String enc = cryptoHandler.encrypt(new String(data, StandardCharsets.UTF_8), null);
        String dec = cryptoHandler.decrypt(enc, null);
        System.out.println(dec);
        assertNotNull(enc);
        assertNotEquals("innehaslo", dec);

    }

    @Test
    void generateSecretKey() throws NoSuchAlgorithmException {
        System.out.println(Arrays.toString(CryptoHandler.generateSecretKey().getEncoded()));
        assertEquals(CryptoHandler.generateSecretKey(), CryptoHandler.generateSecretKey());
    }
}