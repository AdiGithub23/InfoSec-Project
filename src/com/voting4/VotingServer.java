package com.voting4;

//package com.voting3;

import java.security.*;
import java.util.*;

public class VotingServer {
    private Map<String, PublicKey> voterPublicKeys = new HashMap<>();
    private List<byte[][]> encryptedVoteData = new ArrayList<>(); // [encryptedVote, encryptedAesKey]
    private List<byte[]> voteSignatures = new ArrayList<>();
    private Set<String> votedVoters = new HashSet<>();

    // Store public keys
    public void storePublicKeys(Map<String, PublicKey> voterKeys, PublicKey adminPublicKey) {
        this.voterPublicKeys.putAll(voterKeys);
        System.out.println("Public keys stored in server.");
    }

    // Verify voter and store vote
    public boolean verifyAndStoreVote(String voterId, byte[][] encryptedVoteData, byte[] authSignature, byte[] voteSignature, long nonce) throws Exception {
        if (votedVoters.contains(voterId)) {
            System.out.println("Voter " + voterId + " already voted.");
            return false;
        }

        // Verify nonce signature
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(voterPublicKeys.get(voterId));
        sig.update(Long.toString(nonce).getBytes());
        if (!sig.verify(authSignature)) {
            System.out.println("Authentication failed for voter " + voterId);
            return false;
        }

        // Store vote data
        this.encryptedVoteData.add(encryptedVoteData);
        voteSignatures.add(voteSignature);
        votedVoters.add(voterId);
        System.out.println("Vote stored for voter " + voterId);
        return true;
    }

    // Get vote data for tallying
    public List<byte[][]> getEncryptedVoteData() {
        return encryptedVoteData;
    }

    public List<byte[]> getVoteSignatures() {
        return voteSignatures;
    }
}