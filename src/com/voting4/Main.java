package com.voting4;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

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

        // Step 2: Voter registration choice
        System.out.println("\n1: Proceed with the current voters?");
        System.out.println("2: Register new voters?");
        System.out.println("3: Begin new Registration?");
        System.out.print("Your choice: ");
        int choice;
        int numVoters = 0;
        while (true) {
            try {
                choice = Integer.parseInt(scanner.nextLine());
                if (choice >= 1 && choice <= 3) break;
                System.out.println("Invalid choice. Please enter 1, 2, or 3.");
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Please enter a number.");
            }
        }

        // Step 3: Setup
        System.out.println("\nStarting Election Setup...");
        admin.generateKeyPairs();

        if (choice == 1) {
            // Proceed with current voters
            numVoters = admin.loadExistingVoters();
            if (numVoters == 0) {
                System.out.println("No voters found in voters.txt. Please register new voters.");
                scanner.close();
                return;
            }
            System.out.println("Loaded " + numVoters + " existing voters.");
        } else if (choice == 2) {
            // Register a new voter (append)
            numVoters = admin.loadExistingVoters(); // Load existing voters first
            System.out.println("Loaded " + numVoters + " existing voters.");
            while (choice == 2) {
                admin.registerSingleVoter(scanner);
                numVoters = admin.getVoterCount();
                if (numVoters == 0) {
                    System.out.println("No voters registered. Please register new voters.");
                    scanner.close();
                    return;
                }
                System.out.println("\n1: Proceed with the current voters?");
                System.out.println("2: Register new voters?");
                System.out.println("3: Begin new Registration?");
                System.out.print("Your choice: ");
                while (true) {
                    try {
                        choice = Integer.parseInt(scanner.nextLine());
                        if (choice >= 1 && choice <= 3) break;
                        System.out.println("Invalid choice. Please enter 1, 2, or 3.");
                    } catch (NumberFormatException e) {
                        System.out.println("Invalid input. Please enter a number.");
                    }
                }
            }
            if (choice == 3) {
                // Begin new registration
                System.out.print("Type the number of voters: ");
                numVoters = Integer.parseInt(scanner.nextLine());
                admin.registerVoters(numVoters, scanner);
            }
        } else if (choice == 3) {
            // Begin new registration
            System.out.print("Type the number of voters: ");
            numVoters = Integer.parseInt(scanner.nextLine());
            admin.registerVoters(numVoters, scanner);
        }

        server.storePublicKeys(admin.getVoterPublicKeys(), admin.getAdminPublicKey());

        // Step 4: Voting
        System.out.println("\nVoting Phase Started...");
        SecureRandom random = new SecureRandom();
        Set<String> votedVoters = new HashSet<>();
        while (votedVoters.size() < numVoters) {
            System.out.print("Enter voter ID: ");
            String voterId = scanner.nextLine();
            if (!admin.getVoterPublicKeys().containsKey(voterId)) {
                System.out.println("Voter ID " + voterId + " not found in registered voters.");
                continue;
            }
            if (votedVoters.contains(voterId)) {
                System.out.println("Voter " + voterId + " has already voted.");
                continue;
            }
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
                        int choiceVote = Integer.parseInt(scanner.nextLine());
                        if (choiceVote >= 1 && choiceVote <= candidates.size()) {
                            String vote = candidates.get(choiceVote - 1);
                            byte[][] encryptedVoteData = voter.encryptVote(vote);
                            byte[] voteSignature = voter.signVote(vote);
                            if (server.verifyAndStoreVote(voterId, encryptedVoteData, authSignature, voteSignature, nonce)) {
                                votedVoters.add(voterId);
                            }
                            break;
                        } else {
                            System.out.println("Invalid choice. Please enter a number between 1 and " + candidates.size() + ".");
                        }
                    } catch (NumberFormatException e) {
                        System.out.println("Invalid input. Please enter a number.");
                    }
                }
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }

        // Step 5: Tallying
        System.out.println("\nTallying votes...");
        admin.tallyVotes(server.getEncryptedVoteData(), server.getVoteSignatures(), candidates);

        scanner.close();
        System.out.println("Election complete.");
    }
}