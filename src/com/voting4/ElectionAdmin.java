package com.voting4;

//package com.voting3;

import java.security.*;
import java.util.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.security.MessageDigest;
import java.util.Scanner;

public class ElectionAdmin {
    private KeyPair adminKeyPair;
    private Map<String, PublicKey> voterPublicKeys = new HashMap<>();
    private static final String VOTERS_FILE = "voters.txt";

    // Generate RSA key pair for admin
    public void generateKeyPairs() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        this.adminKeyPair = keyGen.generateKeyPair();
        System.out.println("Admin key pair generated.");
    }

    // Register voters and save credentials to file
    public void registerVoters(int numVoters, Scanner scanner) throws Exception {
        new FileWriter(VOTERS_FILE, false).close(); // Clear file
        for (int i = 1; i <= numVoters; i++) {
            System.out.print("Register Voter " + i + ": ");
            String voterId = scanner.nextLine();
            System.out.print("Voter " + i + " Password: ");
            String password = scanner.nextLine();
            KeyPair voterKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            voterPublicKeys.put(voterId, voterKeyPair.getPublic());
            // Hash the password
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedPassword = digest.digest(password.getBytes());
            String hashedPasswordBase64 = Base64.getEncoder().encodeToString(hashedPassword);
            // Save voter credentials to file
            try (PrintWriter out = new PrintWriter(new FileWriter(VOTERS_FILE, true))) {
                out.println(voterId + "," + Base64.getEncoder().encodeToString(voterKeyPair.getPrivate().getEncoded()) + "," + Base64.getEncoder().encodeToString(voterKeyPair.getPublic().getEncoded()) + "," + hashedPasswordBase64);
            }
            System.out.println("Registered Voter: " + voterId);
        }
        System.out.println("\nRegistered All " + numVoters + " voters");
    }

    // Get admin public key
    public PublicKey getAdminPublicKey() {
        return adminKeyPair.getPublic();
    }

    // Get voter public keys
    public Map<String, PublicKey> getVoterPublicKeys() {
        return voterPublicKeys;
    }

    // Decrypt and tally votes (anonymously)
    public void tallyVotes(List<byte[][]> encryptedVoteData, List<byte[]> signatures, List<String> candidates) throws Exception {
        Map<String, Integer> voteCounts = new HashMap<>();
        for (String candidate : candidates) {
            voteCounts.put(candidate, 0);
        }

        for (int i = 0; i < encryptedVoteData.size(); i++) {
            byte[] encryptedVote = encryptedVoteData.get(i)[0];
            byte[] encryptedAesKey = encryptedVoteData.get(i)[1];
            byte[] voteSignature = signatures.get(i);

            // Decrypt AES key with admin's RSA private key
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, adminKeyPair.getPrivate());
            byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            // Decrypt vote with AES
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] decryptedVoteBytes = aesCipher.doFinal(encryptedVote);
            String vote = new String(decryptedVoteBytes);

            // Verify signature against all voter public keys
            boolean verified = false;
            for (PublicKey voterPubKey : voterPublicKeys.values()) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] voteHash = digest.digest(vote.getBytes());
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(voterPubKey);
                sig.update(voteHash);
                if (sig.verify(voteSignature)) {
                    verified = true;
                    break;
                }
            }

            if (verified && candidates.contains(vote)) {
                voteCounts.put(vote, voteCounts.get(vote) + 1);
                System.out.println("Vote for " + vote + " verified (anonymously).");
            } else {
                System.out.println("Invalid vote or signature.");
            }
        }

        // Output results
        System.out.println("Election Results:");
        voteCounts.forEach((candidate, count) -> System.out.println(candidate + ": " + count));
    }
}