//package org.example;
//
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//import java.security.spec.InvalidKeySpecException;
//
//import static org.junit.jupiter.api.Assertions.*;
//
//class DiffieHellmanTest {
//
//    private DiffieHellman alice;
//    private DiffieHellman bob;
//
//    @BeforeEach
//    void setUp() throws NoSuchAlgorithmException, InvalidKeyException {
//        alice = new DiffieHellman();
//        bob = new DiffieHellman();
//    }
//
//    @Test
//    void getPublicKey() {
//        var alicekey = alice.getPublicKey();
//        var bobkey = bob.getPublicKey();
//        assertNotNull(bobkey);
//        assertNotNull(alicekey);
//    }
//
//    @Test
//    void generateSharedSecret() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
//        var alicekey = alice.getPublicKey();
//        var bobkey = bob.getPublicKey();
//        assertArrayEquals(alice.generateSharedSecret(bobkey, true), bob.generateSharedSecret(alicekey, true));
//    }
//    @Test
//    void generateSharedSecretWithFalseLastPhase() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
//        var alicekey = alice.getPublicKey();
//        var bobkey = bob.getPublicKey();
//        assertArrayEquals(alice.generateSharedSecret(bobkey, false), bob.generateSharedSecret(alicekey, false));
//    }
//}