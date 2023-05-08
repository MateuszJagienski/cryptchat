package org.example;


import java.sql.Timestamp;

public class Message {
    private String authorName;
    private String text;
    private byte[] encryptedText;
    private Timestamp timestamp;

    public Message(String authorName, String text, Timestamp timestamp) {
        this.authorName = authorName;
        this.text = text;
        this.timestamp = timestamp;
    }

    public String getAuthorName() {
        return authorName;
    }

    public void setAuthorName(String authorName) {
        this.authorName = authorName;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public byte[] getEncryptedText() {
        return encryptedText;
    }

    public void setEncryptedText(byte[] encryptedText) {
        this.encryptedText = encryptedText;
    }

    public Timestamp getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Timestamp timestamp) {
        this.timestamp = timestamp;
    }
}
