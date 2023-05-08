//package org.example;
//
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//
//import javax.crypto.BadPaddingException;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.NoSuchPaddingException;
//import java.security.InvalidKeyException;
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.NoSuchAlgorithmException;
//
//import static org.junit.jupiter.api.Assertions.*;
//
//class RsaAuthTest {
//
//    @BeforeEach
//    void setUp() {
//    }
//
//    @Test
//    void sign() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
//        // Generate key pair
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//      //  keyPairGenerator.initialize(2048);
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//
//        // Create RSAEncryption instance
//
//        RsaAuth rsaEncryption = new RsaAuth();
//
//        // Message to sign
//        byte[] message = "This is a test message".getBytes();
//
//        // Sign message
//        byte[] signature = rsaEncryption.signWithPrivateKey(message, keyPair.getPrivate());
//
//        // Verify signature
//        String decryptedMessage = rsaEncryption.verifyWithPublicKey(signature, keyPair.getPublic()); // TODO
//
//        // Check that decrypted message matches original message
//        assertEquals("This is a test message", decryptedMessage);
//    }
//
//
//
//    @Test
//    void verify() {
//    }
//}