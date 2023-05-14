package org.example;

import org.example.security.DiffieHellman;
import org.example.security.KeysGenerator;
import org.example.utils.BytesToStringConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.*;

class DiffieHellmanTest {

    private DiffieHellman alice;
    private DiffieHellman bob;
    private KeyPair aliceKeyPair;
    private KeyPair bobKeyPair;
    @BeforeEach
    void setUp() throws NoSuchAlgorithmException, InvalidKeyException {
        aliceKeyPair = KeysGenerator.generateDhKeyPair(2048);
        bobKeyPair = KeysGenerator.generateDhKeyPair(2048);
        alice = new DiffieHellman(aliceKeyPair.getPrivate());
        bob = new DiffieHellman(bobKeyPair.getPrivate());
    }

    @Test
    void generateSharedSecret() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        assertArrayEquals(alice.generateSharedSecret(bobKeyPair.getPublic().getEncoded(), true), bob.generateSharedSecret(aliceKeyPair.getPublic().getEncoded(), true));
    }
    @Test
    void generateSharedSecretWithFalseLastPhase() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        assertArrayEquals(alice.generateSharedSecret(bobKeyPair.getPublic().getEncoded(), false), bob.generateSharedSecret(aliceKeyPair.getPublic().getEncoded(), false));
    }

    @Test
    void sharedSecretBetween3Parties() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        var daveKeyPair = KeysGenerator.generateDhKeyPair(2048);
        var daveDh = new DiffieHellman(daveKeyPair.getPrivate());
        var ak1 = alice.generateSharedSecret(daveKeyPair.getPublic().getEncoded(), false);

        var bk1 = bob.generateSharedSecret(aliceKeyPair.getPublic().getEncoded(), false);
        var dk1 = daveDh.generateSharedSecret(bobKeyPair.getPublic().getEncoded(), false);

        var as = alice.generateSharedSecret(dk1, true);
        var bs = bob.generateSharedSecret(ak1, true);
        var ds = daveDh.generateSharedSecret(bk1, true);

        System.out.println(BytesToStringConverter.bytesToString(ds));
        System.out.println(BytesToStringConverter.bytesToString(bs));
        System.out.println(BytesToStringConverter.bytesToString(as));
        assertArrayEquals(ds, as);
        assertArrayEquals(ds, bs);
    }
}