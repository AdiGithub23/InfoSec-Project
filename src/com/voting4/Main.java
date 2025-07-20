package com.voting4;

//package com.voting3;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        ElectionAdmin admin = new ElectionAdmin();
        VotingServer server = new VotingServer();

        // Step 1: Get number of candidates and their names
        System.out.print("Type the number of Candidates: ");
        int numCandidates = Integer.parseInt(scanner.nextLine());
        List<String> candidates = new ArrayList<>();
        for (int i = 0; i < numCandidates; i++) {
            System.out.print("Enter name of candidate " + (i + 1) + ": ");
            String candidate = scanner.nextLine();
            candidates.add(candidate);
        }

        // Step 2: Get number of voters
        System.out.print("Type the number of voters: ");
        int numVoters = Integer.parseInt(scanner.nextLine());

        // Step 3: Setup
        System.out.println("\nStarting Election Setup...");
        admin.generateKeyPairs();
        admin.registerVoters(numVoters, scanner);
        server.storePublicKeys(admin.getVoterPublicKeys(), admin.getAdminPublicKey());

        // Step 4: Voting
        System.out.println("\nVoting Phase Started...");
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < numVoters; i++) {
            while (true) {
                System.out.print("Enter voter ID: ");
                String voterId = scanner.nextLine();
                System.out.print(voterId + " Password: ");
                String password = scanner.nextLine();
                try {
                    Voter voter = new Voter(voterId, password, admin.getAdminPublicKey());
                    long nonce = random.nextLong();
                    byte[] authSignature = voter.authenticate(nonce);
                    System.out.println("Choose a candidate by number:");
                    for (int j = 0; j < candidates.size(); j++) {
                        System.out.print((j + 1) + ": " + candidates.get(j));
                        if (j < candidates.size() - 1) System.out.print(" | ");
                    }
                    System.out.println(" |");
                    while (true) {
                        try {
                            System.out.print("Enter your choice: ");
                            int choice = Integer.parseInt(scanner.nextLine());
                            if (choice >= 1 && choice <= candidates.size()) {
                                String vote = candidates.get(choice - 1);
                                byte[][] encryptedVoteData = voter.encryptVote(vote);
                                byte[] voteSignature = voter.signVote(vote);
                                server.verifyAndStoreVote(voterId, encryptedVoteData, authSignature, voteSignature, nonce);
                                break;
                            } else {
                                System.out.println("Invalid choice. Please enter a number between 1 and " + candidates.size() + ".");
                            }
                        } catch (NumberFormatException e) {
                            System.out.println("Invalid input. Please enter a number.");
                        }
                    }
                    break; // Exit login loop on successful vote
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                }
            }
        }

        // Step 5: Tallying
        System.out.println("\nTallying votes...");
        admin.tallyVotes(server.getEncryptedVoteData(), server.getVoteSignatures(), candidates);

        scanner.close();
        System.out.println("Election complete.");
    }
}
