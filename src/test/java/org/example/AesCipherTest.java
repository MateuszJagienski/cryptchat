package org.example;

import org.example.security.AesCipher;
import org.example.security.DiffieHellman;
import org.example.security.KeysGenerator;
import org.example.utils.HashGenerator;
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
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AesCipherTest {

    private SecretKey secretKey;
    @BeforeEach
    void setUp() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        var u1 = KeysGenerator.generateDhKeyPair(2048);
        var u2 = KeysGenerator.generateDhKeyPair(2048);


        DiffieHellman Dh1 = new DiffieHellman(u1.getPrivate());
        DiffieHellman Dh2 = new DiffieHellman(u2.getPrivate());

        var secret = Dh1.generateSharedSecret(u1.getPublic().getEncoded(), true);

        var key = HashGenerator.hashMessageSHA(secret, "SHA-256", 16);

        secretKey = new SecretKeySpec(key, "AES");
    }
    @Test
    void encrypt() throws Exception {
        byte[] bytes = "Hello worldlopki".getBytes(StandardCharsets.UTF_8);
        String encryptedText = AesCipher.encrypt(new String(bytes, StandardCharsets.UTF_8), secretKey);
        assertNotNull(encryptedText);
        assertNotEquals(0, encryptedText.length());
    }

    @Test
    void encrypt1() throws Exception {
        byte[] bytes = "0".getBytes(StandardCharsets.UTF_8);
        String encryptedText = AesCipher.encrypt(new String(bytes, StandardCharsets.UTF_8), secretKey);
        assertNotNull(encryptedText);
        assertNotEquals(0, encryptedText.length());
        assertTrue(196 <= encryptedText.length());
    }

    @Test
    void decrypt() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        byte[] data = "haslo".getBytes(StandardCharsets.UTF_8);
        String enc = AesCipher.encrypt(new String(data, StandardCharsets.UTF_8), secretKey);
        String dec = AesCipher.decrypt(enc, secretKey);
        assertNotNull(enc);
        assertEquals("haslo", dec);
    }

    @Test
    void decrypt1() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        byte[] data = "asd".getBytes(StandardCharsets.UTF_8);
        String enc = AesCipher.encrypt(new String(data, StandardCharsets.UTF_8), null);
        String dec = AesCipher.decrypt(enc, null);
        assertNotNull(enc);
        assertNotEquals("innehaslo", dec);

    }
}