package com.kwyd.knowyourdata;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Scanner;

public class Main {
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_RESET = "\u001B[00m";

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            return;
        }

        String command = args[0].toLowerCase();
        Path input = Path.of(args[1]);

        try {
            if (command.equals("encrypt")) {
                Path output = args.length > 2 ? Path.of(args[2]) : Path.of(args[1] + ".en.emq");
                handleEncryption(input, output);
            } else if (command.equals("decrypt")) {
                Path output = args.length > 2 ? Path.of(args[2]) : Path.of(args[1].replace(".en.emq", ".en.dec"));
                handleDecryption(input, output);
            } else {
                System.out.println("Unknown command: " + command);
            }
        } catch (Exception e) {
            System.err.println(ANSI_RED + "CRITICAL ERROR: " + e.getMessage() + ANSI_RESET);
        }
    }

    private static void handleEncryption(Path in, Path out) throws Exception {
        System.out.println("--- SECURE ENCRYPTION MODE ---");
        char[] pass;
        while (true) {
            pass = promptPassword("Set a passkey for encryption: ");
            Crypto.Strength strength = Crypto.checkStrength(pass);
            
            if (strength == Crypto.Strength.STRONG) {
                System.out.println(ANSI_GREEN + "Status: STRONG Passkey Accepted." + ANSI_RESET);
                break;
            } else {
                System.out.println(ANSI_RED + "Status: " + strength + " Passkey Rejected." + ANSI_RESET);
                System.out.println("Hint: Use 12+ chars, including Uppercase, Numbers, and Symbols.");
                Crypto.zero(pass);
            }
        }
        
        Crypto.encrypt(in, out, pass);
        Crypto.zero(pass);
        System.out.println(ANSI_GREEN + "Success: File secured at " + out + ANSI_RESET);
    }

    private static void handleDecryption(Path in, Path out) throws Exception {
        System.out.println("--- SECURE DECRYPTION MODE ---");
        char[] pass = promptPassword("Enter passkey to unlock data: ");
        
        Crypto.decrypt(in, out, pass);
        Crypto.zero(pass);
        System.out.println(ANSI_GREEN + "Success: Data extracted to " + out + ANSI_RESET);
    }

    private static char[] promptPassword(String prompt) {
        System.out.print(prompt);
        var console = System.console();
        if (console != null) {
            return console.readPassword();
        }
        // Fallback for IDEs/Non-TTY environments
        return new Scanner(System.in).nextLine().toCharArray();
    }

    private static void printUsage() {
        System.out.println("Strong Encryption Tool v2.0");
        System.out.println("Usage:");
        System.out.println("  encrypt <file> [output]");
        System.out.println("  decrypt <file.en.emq> [output]");
    }
}
