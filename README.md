# InfoSec-Project

🌟 SecureVotingMVP: A Secure E-Voting System in Java 🌟
Welcome to SecureVotingMVP, a robust electronic voting system built in Java, designed to ensure security, anonymity, and integrity in digital elections. This project leverages cryptographic primitives to create a trustworthy voting platform, perfect for learning about secure system design! 🚀
🔒 Key Features of SecureVotingMVP

🔐 Hybrid Encryption for Confidentiality:Votes are encrypted using AES for efficiency and RSA to securely encrypt the AES key, ensuring only the election admin can decrypt votes. 🛡️

🖋️ Digital Signatures for Integrity:Every vote is signed with SHA-256 and RSA, guaranteeing no tampering and verifying authenticity without compromising voter anonymity. ✅

🕵️‍♂️ Anonymous Vote Tallying:Votes are tallied without linking to voter identities, preserving privacy while ensuring accurate results. 🗳️

🔑 Strong Authentication:Voters authenticate using hashed passwords (SHA-256) and nonce-based RSA signatures, preventing unauthorized or duplicate votes. 🔐

📂 Persistent Voter Registry:Voter credentials (IDs, RSA key pairs, hashed passwords) are stored in voters.txt, allowing reuse across sessions. 📋

🛠️ Flexible Voter Management:Choose to:  

Proceed with existing voters 🧑‍🤝‍🧑  
Add new voters to the current list ➕  
Start a fresh voter registration 🔄


📢 Transparent Cryptographic Outputs:Displays Base64-encoded admin/voter key pairs, encrypted votes, signatures, and decrypted votes for debugging and transparency. 💻


🌈 Project Overview
SecureVotingMVP demonstrates how cryptographic techniques (RSA, AES, SHA-256) can be combined to build a secure, verifiable, and anonymous e-voting system. The program guides users through candidate setup, voter registration (or reuse), voting, and anonymous vote tallying, all while maintaining robust security principles.
💻 How to Run

Clone the Repository:  
git clone https://github.com/your-username/SecureVotingMVP.git
cd SecureVotingMVP


Compile and Run:Ensure Java is installed, then compile and run the main class:
javac com/voting4/*.java
java com.voting4.Main


Follow the Prompts:  

Enter the number of candidates and their names.  
Choose to proceed with existing voters, add a new voter, or start a new registration.  
Authenticate voters and cast votes securely.  
View the election results.



📋 Requirements

Java 8 or higher
Write permissions for voters.txt in the project directory
