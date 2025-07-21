package com.voting4;

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
        System.out.println("Admin Public Key: " + Base64.getEncoder().encodeToString(adminKeyPair.getPublic().getEncoded()));
        System.out.println("Admin Private Key: " + Base64.getEncoder().encodeToString(adminKeyPair.getPrivate().getEncoded()));
    }

    // Load existing voters from voters.txt
    public int loadExistingVoters() throws Exception {
        voterPublicKeys.clear();
        File file = new File(VOTERS_FILE);
        if (!file.exists()) {
            return 0;
        }
        int voterCount = 0;
        try (BufferedReader br = new BufferedReader(new FileReader(VOTERS_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length == 4) {
                    String voterId = parts[0];
                    PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new java.security.spec.X509EncodedKeySpec(Base64.getDecoder().decode(parts[2])));
                    voterPublicKeys.put(voterId, publicKey);
                    voterCount++;
                }
            }
        }
        return voterCount;
    }

    // Register a single voter (append to file)
    public void registerSingleVoter(Scanner scanner) throws Exception {
        System.out.print("Register New Voter: ");
        String voterId = scanner.nextLine();
        if (voterPublicKeys.containsKey(voterId)) {
            System.out.println("Voter ID " + voterId + " already exists.");
            return;
        }
        System.out.print("Voter Password: ");
        String password = scanner.nextLine();
        KeyPair voterKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        voterPublicKeys.put(voterId, voterKeyPair.getPublic());
        // Hash the password
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedPassword = digest.digest(password.getBytes());
        String hashedPasswordBase64 = Base64.getEncoder().encodeToString(hashedPassword);
        // Append voter credentials to file
        try (PrintWriter out = new PrintWriter(new FileWriter(VOTERS_FILE, true))) {
            out.println(voterId + "," + Base64.getEncoder().encodeToString(voterKeyPair.getPrivate().getEncoded()) + "," + Base64.getEncoder().encodeToString(voterKeyPair.getPublic().getEncoded()) + "," + hashedPasswordBase64);
        }
        System.out.println("Registered Voter: " + voterId);
        System.out.println("Voter " + voterId + " Public Key: " + Base64.getEncoder().encodeToString(voterKeyPair.getPublic().getEncoded()));
        System.out.println("Voter " + voterId + " Private Key: " + Base64.getEncoder().encodeToString(voterKeyPair.getPrivate().getEncoded()));
    }

    // Register voters and save credentials to file (new registration)
    public void registerVoters(int numVoters, Scanner scanner) throws Exception {
        new FileWriter(VOTERS_FILE, false).close(); // Clear file
        voterPublicKeys.clear();
        for (int i = 1; i <= numVoters; i++) {
            System.out.print("Register Voter " + i + ": ");
            String voterId = scanner.nextLine();
            if (voterPublicKeys.containsKey(voterId)) {
                System.out.println("Voter ID " + voterId + " already exists. Please choose a different ID.");
                i--;
                continue;
            }
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
            System.out.println("Voter " + voterId + " Public Key: " + Base64.getEncoder().encodeToString(voterKeyPair.getPublic().getEncoded()));
            System.out.println("Voter " + voterId + " Private Key: " + Base64.getEncoder().encodeToString(voterKeyPair.getPrivate().getEncoded()));
        }
        System.out.println("\nRegistered All " + numVoters + " voters");
    }

    // Get the number of registered voters
    public int getVoterCount() {
        return voterPublicKeys.size();
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

        System.out.println("Real Votes:");
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
            System.out.println("Decrypted Vote: " + vote);

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