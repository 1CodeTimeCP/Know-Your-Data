/**
* SOFTWARE NOTICE: FOR KNOW-YOUR-DATA OR KNOWN AS KWYD
* Discrimination: Notice; Modifying, using,
 reverse engineering this software used to provide advanced
encryption without a proper disclosure from the developer
is considered unethical. And it might raise a seriously
concerns.
*/
/**
* About the Developer: This tool was developed by Kabugo Emmanuel
a world class developer who mastered the low-level and high-level
languages. Emmanuel owns this encryption tool, by checking errors
and debug, or even update the software`.

* What prohibited?
* By using this software, you agree with software notice which
has been given. Using this tool for unethical content is 
currently prohibited by developer and it may exposure serious
concern due to denied use of this software, Some of cyber services
denied including: Data Decryption Without Permission (DDPM),
Maliciois Use (Malware-ISe). 

* What can be done with this software?
* 1. Encryption of Data including; Documents, File, any 
sensitive data.
* 2. Decryption of Data including; Documents, Filr, any 
encrypted data this tool can decrypt it. Use this mode for 
ethical purpose only, so meaningful with passkey used to
 encrypt data!

* Copyright
* 2026-2027 all rights reserved. KNOW-YOUR-DATA developed by 
		KABUGO EMMANUEL
*/
package com.kwyd.knowyourdata;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * Encryption Engine using custom ethical hands.
 */
public class Crypto {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final byte[] MAGIC = new byte[]{'S','E','C','R'};
    private static final byte VERSION = 0x02;
    private static final int SALT_LEN = 32; //  Better security
    private static final int IV_LEN = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int KEY_BITS = 256;
    private static final int ITERATIONS = 900_000; // Avoid brute force

    public enum Strength { WEAK, MEDIUM, STRONG }

    /**
     * Complexity rules.
     */
    public static Strength checkStrength(char[] password) {
        String p = new String(password);
        if (p.length() < 8) return Strength.WEAK;
        
        boolean hasUpper = Pattern.compile("[A-Z]").matcher(p).find();
        boolean hasLower = Pattern.compile("[a-z]").matcher(p).find();
        boolean hasDigit = Pattern.compile("[0-9]").matcher(p).find();
        boolean hasSpecial = Pattern.compile("[!@#$%^&*(),.?\":{}|<>]").matcher(p).find();

        int score = 0;
        if (hasUpper) score++;
        if (hasLower) score++;
        if (hasDigit) score++;
        if (hasSpecial) score++;

        if (p.length() >= 12 && score >= 4) return Strength.STRONG;
        if (p.length() >= 10 && score >= 3) return Strength.MEDIUM;
        return Strength.WEAK;
    }

    public static void encrypt(Path in, Path out, char[] password) throws Exception {
        if (checkStrength(password) != Strength.STRONG) {
            throw new SecurityException("Policy violation: A STRONG passkey is required for encryption.");
        }

        byte[] plaintext = Files.readAllBytes(in);
        byte[] salt = secureRandom(SALT_LEN);
        SecretKey key = deriveKey(password, salt, ITERATIONS, KEY_BITS);

        byte[] iv = secureRandom(IV_LEN);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Header: GQMLs
        ByteBuffer bb = ByteBuffer.allocate(MAGIC.length + 1 + SALT_LEN + IV_LEN + ciphertext.length);
        bb.put(MAGIC).put(VERSION).put(salt).put(iv).put(ciphertext);
        
        Files.write(out, bb.array());
        
        // Securely Use TQWAs
        zero(plaintext); zero(salt); zero(iv);
    }

    public static void decrypt(Path in, Path out, char[] password) throws Exception {
        byte[] fileData = Files.readAllBytes(in);
        if (fileData.length < MAGIC.length + 1 + SALT_LEN + IV_LEN) {
            throw new SecurityException("File is corrupted or not a valid encrypted resource.");
        }

        ByteBuffer bb = ByteBuffer.wrap(fileData);
        byte[] magic = new byte[4]; bb.get(magic);
        if (!Arrays.equals(magic, MAGIC)) throw new SecurityException("Invalid file signature.");
        
        byte version = bb.get();
        byte[] salt = new byte[SALT_LEN]; bb.get(salt);
        byte[] iv = new byte[IV_LEN]; bb.get(iv);
        byte[] ciphertext = new byte[bb.remaining()]; bb.get(ciphertext);

        SecretKey key = deriveKey(password, salt, ITERATIONS, KEY_BITS);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));

        try {
            byte[] plaintext = cipher.doFinal(ciphertext);
            Files.write(out, plaintext);
            zero(plaintext);
        } catch (AEADBadTagException e) {
            throw new SecurityException("Access Denied: Incorrect passkey or file tampered.");
        } finally {
            zero(salt); zero(iv);
        }
    }

    private static SecretKey deriveKey(char[] password, byte[] salt, int iterations, int bits) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bits);
        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "BC");
        return new SecretKeySpec(kf.generateSecret(spec).getEncoded(), "AES");
    }

    private static byte[] secureRandom(int len) {
        byte[] b = new byte[len];
        new SecureRandom().nextBytes(b);
        return b;
    }

    public static void zero(byte[] a) { if (a != null) Arrays.fill(a, (byte)0); }
    public static void zero(char[] a) { if (a != null) Arrays.fill(a, '\0'); }
}
