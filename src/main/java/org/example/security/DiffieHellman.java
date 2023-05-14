package org.example.security;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class DiffieHellman {

    private final KeyAgreement keyAgreement;
    public static final String ALGORITHM = "DH";

    public DiffieHellman(PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        keyAgreement = KeyAgreement.getInstance(ALGORITHM);
        keyAgreement.init(key);
    }

    public byte[] generateSharedSecret(byte[] remotePublicKey, boolean lastPhase) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(remotePublicKey);
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        var key = keyAgreement.doPhase(publicKey, lastPhase);
        return lastPhase ? keyAgreement.generateSecret() : key.getEncoded();
    }
}
