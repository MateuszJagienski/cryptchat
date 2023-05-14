package org.example;

import org.example.security.KeysGenerator;
import org.example.security.RsaAuth;
import org.example.utils.BytesToStringConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class RsaAuthTest {

    @BeforeEach
    void setUp() {
    }

    @Test
    void sign() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // Generate key pair
        KeyPair keyPair = KeysGenerator.generateRsaKeyPair(4096);

        // Message to sign
        byte[] message = "This is a test message".getBytes();

        // Sign message
        byte[] signature = RsaAuth.signWithPrivateKey(message, keyPair.getPrivate());

        // Verify signature
        byte[] verified = RsaAuth.verifyWithPublicKey(signature, keyPair.getPublic()); // TODO

        // Check that decrypted message matches original message
        assertEquals("This is a test message", BytesToStringConverter.bytesToString(verified));
    }
    @Test()
    void verifyWithWrongKey() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // Generate key pair
        KeyPair keyPair = KeysGenerator.generateRsaKeyPair(4096);
        KeyPair keyPair1 = KeysGenerator.generateRsaKeyPair(4096);

        // Message to sign
        byte[] message = "This is a test message".getBytes();

        // Sign message
        byte[] signature = RsaAuth.signWithPrivateKey(message, keyPair.getPrivate());

        // Verify signature
        assertThrows(BadPaddingException.class, () -> RsaAuth.verifyWithPublicKey(signature, keyPair1.getPublic()));
    }

    @Test
    void verify() {
    }
}