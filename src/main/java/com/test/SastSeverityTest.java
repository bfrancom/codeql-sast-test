package com.test;

// DEV-1042: CodeQL vs Datadog SAST comparison test.
// Contains deliberate vulnerabilities at multiple severity levels.

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.MessageDigest;

/**
 * DELIBERATELY INSECURE test file.
 * Every vulnerability below is intentional for comparing SAST tools.
 */
public class SastSeverityTest {

    // CRITICAL: SQL Injection - unsanitized user input in SQL query
    public ResultSet getUser(Connection conn, String userId) throws Exception {
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
    }

    // CRITICAL: Command Injection - unsanitized input passed to process exec
    public Process runCommand(String userInput) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "ls " + userInput);
        return pb.start();
    }

    // HIGH: Insecure deserialization - deserializing untrusted data
    public Object deserialize(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ObjectInputStream ois = new ObjectInputStream(fis);
        return ois.readObject();
    }

    // HIGH: Weak cryptography - using DES
    public byte[] encrypt(byte[] data) throws Exception {
        SecretKeySpec key = new SecretKeySpec("12345678".getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // MEDIUM: Weak hashing - using MD5
    public byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }

    // MEDIUM: Hardcoded credentials
    private static final String DB_PASSWORD = "admin123";

    public Connection getConnection() throws Exception {
        return DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/db", "root", DB_PASSWORD
        );
    }

    // LOW: Empty catch block
    public void processData(String data) {
        try {
            Integer.parseInt(data);
        } catch (NumberFormatException e) {
            // silently ignored
        }
    }

    // LOW: System.out.println instead of proper logging
    public void log(String message) {
        System.out.println("LOG: " + message);
    }
}
