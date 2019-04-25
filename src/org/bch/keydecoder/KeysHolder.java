package org.bch.keydecoder;

public class KeysHolder {
    private String publicKey;
    private String privateKey;

    public KeysHolder(String publicKey, String privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }
}
