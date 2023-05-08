package org.example;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class User {
    private String name;
    private KeyPair keyPairRsa;

    private KeyPair keyPairDh;

    private byte[] sharedSecret;

    public User(String name, KeyPair keyPairRsa) {
        this.name = name;
        this.keyPairRsa = keyPairRsa;
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
