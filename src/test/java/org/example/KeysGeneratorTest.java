package org.example;

import org.example.security.KeysGenerator;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class KeysGeneratorTest {

    @Test
    void rsaKeys() throws NoSuchAlgorithmException {
        var keyPair1 = KeysGenerator.generateRsaKeyPair(2048);
        var keyPair2 = KeysGenerator.generateRsaKeyPair(2048);
        assertNotEquals(keyPair1.getPrivate(), keyPair2.getPrivate());

        assertNotEquals(keyPair1.getPublic(), keyPair2.getPublic());
        System.out.println(Arrays.toString(keyPair1.getPrivate().getEncoded()));
        System.out.println(Arrays.toString(keyPair2.getPrivate().getEncoded()));
        assertFalse(Arrays.equals(keyPair1.getPrivate().getEncoded(), keyPair2.getPrivate().getEncoded()));
    }
}
