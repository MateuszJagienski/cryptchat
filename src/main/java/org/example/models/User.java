package org.example.models;

import org.example.security.DiffieHellman;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class User {
    private String name;
    private KeyPair keyPairRsa;

    private KeyPair keyPairDh;

    private byte[] sharedSecret;

    private SecretKey secretAesKey;
    private DiffieHellman diffieHellman;

    public DiffieHellman getDiffieHellman() {
        return diffieHellman;
    }

    public void setDiffieHellman(DiffieHellman diffieHellman) {
        this.diffieHellman = diffieHellman;
    }

    public User(String name, KeyPair keyPairRsa) {
        this.name = name;
        this.keyPairRsa = keyPairRsa;
    }

    public SecretKey getSecretAesKey() {
        return secretAesKey;
    }

    public void setSecretAesKey(SecretKey secretAesKey) {
        this.secretAesKey = secretAesKey;
    }

    public KeyPair getKeyPairDh() {
        return keyPairDh;
    }

    public void setKeyPairDh(KeyPair keyPairDh) {
        this.keyPairDh = keyPairDh;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public KeyPair getKeyPairRsa() {
        return keyPairRsa;
    }

    public void setKeyPairRsa(KeyPair keyPairRsa) {
        this.keyPairRsa = keyPairRsa;
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    public void setSharedSecret(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }
}
