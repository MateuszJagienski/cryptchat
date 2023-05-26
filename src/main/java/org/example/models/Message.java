package org.example.models;


import java.sql.Timestamp;

public class Message{
    private String authorName;
    private String recipientName;
    private String encryptedText;
    private byte[] signature;
    private Timestamp timestamp;
    private byte[] encryptedAesKey;

    public byte[] getEncryptedAesKey() {
        return encryptedAesKey;
    }

    public void setEncryptedAesKey(byte[] encryptedAesKey) {
        this.encryptedAesKey = encryptedAesKey;
    }

    public Message(String authorName, Timestamp timestamp) {
        this.authorName = authorName;
        this.timestamp = timestamp;
    }

    public Message(String authorName) {
        this.authorName = authorName;
    }

    public Message() {
    }

    public String getRecipientName() {
        return recipientName;
    }

    public void setRecipientName(String recipientName) {
        this.recipientName = recipientName;
    }

    public String getAuthorName() {
        return authorName;
    }

    public void setAuthorName(String authorName) {
        this.authorName = authorName;
    }

    public String getEncryptedText() {
        return encryptedText;
    }

    public void setEncryptedText(String encryptedText) {
        this.encryptedText = encryptedText;
    }

    public Timestamp getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Timestamp timestamp) {
        this.timestamp = timestamp;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }
}
