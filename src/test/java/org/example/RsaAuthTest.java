package org.example;

import org.example.security.DiffieHellman;
import org.example.security.KeysGenerator;
import org.example.security.RsaAuth;
import org.example.utils.BytesToStringConverter;
import org.example.utils.HashGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class RsaAuthTest {

    @BeforeEach
    void setUp() {
    }

    @Test
    void sign() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, SignatureException, NoSuchProviderException {
        // Generate key pair
        KeyPair keyPair = KeysGenerator.generateRsaKeyPair(2048);

        // Message to sign
        byte[] message = "This is a test message".getBytes();
        byte[] hashedMessage = HashGenerator.hashMessageSHA(message, "SHA-256");
        // Sign message
        byte[] signature = RsaAuth.signWithPrivateKey(hashedMessage, keyPair.getPrivate());

        // Verify signature
        byte[] verified = RsaAuth.verifyWithPublicKey(signature, keyPair.getPublic());

        // Check that decrypted message matches original message

        assertArrayEquals(hashedMessage, verified);
    }

    @Test
    void signTwice() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidKeyException, NoSuchProviderException {
        KeyPair keyPair = KeysGenerator.generateRsaKeyPair(2048);
        KeyPair keyPairRemote = KeysGenerator.generateRsaKeyPair(2048);

        byte[] message = "This is a test message".getBytes();
        byte[] hashedMessage = HashGenerator.hashMessageSHA(message, "SHA-256");
        byte[] signature = RsaAuth.signWithPrivateKey(hashedMessage, keyPair.getPrivate());
        byte[] signatureWithPublicKey = RsaAuth.signWithPublicKey(signature, keyPairRemote.getPublic());

        byte[] verifyFirst = RsaAuth.verifyWithPrivateKey(signatureWithPublicKey, keyPairRemote.getPrivate());
        assertArrayEquals(verifyFirst, signature);
        byte[] verifySecond = RsaAuth.verifyWithPublicKey(verifyFirst, keyPair.getPublic());
        assertArrayEquals(verifySecond, hashedMessage);
    }

    @Test
    void signTwice1() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidKeyException, NoSuchProviderException {
        KeyPair keyPair = KeysGenerator.generateRsaKeyPair(2048);
        KeyPair keyPairRemote = KeysGenerator.generateRsaKeyPair(2048);

        var message = "This is a test sdgdfsgdfgsdfgdfgsdfgsdgdfsgdfgsdfgdfgsdfgsdgdfsgdfgsdfgdfgsdfgsdgdfsgdfgsdfgdfgsdfgsdgdfsgdfgsdfgdfgsdfg";
        byte[] hashedMessage = HashGenerator.hashMessageSHA(message, "SHA-256");
        byte[] signature = RsaAuth.signWithPrivateKey(hashedMessage, keyPair.getPrivate());
        byte[] signatureWithPublicKey = RsaAuth.signWithPublicKey(signature, keyPairRemote.getPublic());

        byte[] verifyFirst = RsaAuth.verifyWithPrivateKey(signatureWithPublicKey, keyPairRemote.getPrivate());
        assertArrayEquals(verifyFirst, signature);
        byte[] verifySecond = RsaAuth.verifyWithPublicKey(verifyFirst, keyPair.getPublic());
        assertArrayEquals(verifySecond, hashedMessage);
    }

    @Test
    void signPublicDhKey() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, NoSuchProviderException {
        KeyPair keyPair = KeysGenerator.generateDhKeyPair(2048);
        KeyPair keyPairRemote = KeysGenerator.generateRsaKeyPair(2048);
        DiffieHellman diffieHellman = new DiffieHellman(keyPair.getPrivate());
        byte[] sign = RsaAuth.signWithPrivateKey(keyPair.getPublic().getEncoded(), keyPairRemote.getPrivate());
        byte[] verify = RsaAuth.verifyWithPublicKey(sign, keyPairRemote.getPublic());
        assertArrayEquals(keyPair.getPublic().getEncoded(), verify);
    }

    @Test
    void signAesKey() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidKeyException, NoSuchProviderException {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        var aesKey = keygen.generateKey();
        KeyPair rsaKeyPair = KeysGenerator.generateRsaKeyPair(2048);
        byte[] sign = RsaAuth.signWithPrivateKey(aesKey.getEncoded(), rsaKeyPair.getPrivate());
        byte[] verify = RsaAuth.verifyWithPublicKey(sign, rsaKeyPair.getPublic());
        assertArrayEquals(aesKey.getEncoded(), verify);
    }
    @Test()
    void verifyWithWrongKey() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, SignatureException, NoSuchProviderException {
        // Generate key pair
        KeyPair keyPair = KeysGenerator.generateRsaKeyPair(2048);
        KeyPair keyPair1 = KeysGenerator.generateRsaKeyPair(2048);

        // Message to sign
        byte[] message = "This is a test message".getBytes();

        // Sign message
        byte[] signature = RsaAuth.signWithPrivateKey(message, keyPair.getPrivate());
        //assertArrayEquals(message, RsaAuth.verifyWithPublicKey(signature, keyPair1.getPublic()));
        // Verify signature
        System.out.println(BytesToStringConverter.bytesToHex(message));
        System.out.println(BytesToStringConverter.bytesToHex(signature));
        System.out.println(BytesToStringConverter.bytesToHex(RsaAuth.verifyWithPublicKey(signature, keyPair1.getPublic())));
        System.out.println(BytesToStringConverter.bytesToHex(RsaAuth.verifyWithPublicKey(signature, keyPair.getPublic())));
        assertFalse(Arrays.equals(message, RsaAuth.verifyWithPublicKey(signature, keyPair1.getPublic())));
    }

    @Test
    void verify() {
    }
}