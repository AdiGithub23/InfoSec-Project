package com.voting4;

//package com.voting3;

import java.security.*;
import javax.crypto.*;
import java.util.Base64;
import java.io.*;
import java.security.MessageDigest;

public class Voter {
    private String voterId;
    private PrivateKey privateKey;
    private PublicKey adminPublicKey;

    // Load voter credentials from file and verify password
    public Voter(String voterId, String password, PublicKey adminPublicKey) throws Exception {
        this.voterId = voterId;
        this.adminPublicKey = adminPublicKey;
        String hashedPasswordBase64 = null;
        try (BufferedReader br = new BufferedReader(new FileReader("voters.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts[0].equals(voterId)) {
                    // Verify password
                    String storedHashedPassword = parts[3];
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] hashedInputPassword = digest.digest(password.getBytes());
                    hashedPasswordBase64 = Base64.getEncoder().encodeToString(hashedInputPassword);
                    if (!hashedPasswordBase64.equals(storedHashedPassword)) {
                        throw new Exception("Incorrect password for voter " + voterId);
                    }
                    this.privateKey = KeyFactory.getInstance("RSA").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(Base64.getDecoder().decode(parts[1])));
                    break;
                }
            }
        }
        if (privateKey == null) throw new Exception("Voter ID not found: " + voterId);
        System.out.println("Voter " + voterId + " initialized.");

        System.out.println("Voter ID: " + voterId);
        System.out.println("Hashed Password: " + hashedPasswordBase64);
    }

    // Authenticate with nonce
    public byte[] authenticate(long nonce) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(Long.toString(nonce).getBytes());
        byte[] signature = sig.sign();
        System.out.println("Voter " + voterId + " authenticated with nonce.");
        return signature;
    }

    // Encrypt vote with AES and RSA (hybrid encryption)
    public byte[][] encryptVote(String vote) throws Exception {
        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();

        // Encrypt vote with AES
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedVote = aesCipher.doFinal(vote.getBytes());

        // Encrypt AES key with admin's RSA public key
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, adminPublicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        System.out.println("Voter " + voterId + " encrypted vote: " + vote);
        System.out.println("AES Encrypted Vote: " + Base64.getEncoder().encodeToString(encryptedVote));
        System.out.println("RSA Encrypted AES Key: " + Base64.getEncoder().encodeToString(encryptedAesKey));
        
        return new byte[][] { encryptedVote, encryptedAesKey };
    }

    // Sign vote
    public byte[] signVote(String vote) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] voteHash = digest.digest(vote.getBytes());
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(voteHash);
        byte[] signature = sig.sign();
        System.out.println("Voter " + voterId + " signed vote.");
        System.out.println("Vote Signature: " + Base64.getEncoder().encodeToString(signature));
        return signature;
    }

    public String getVoterId() {
        return voterId;
    }
}