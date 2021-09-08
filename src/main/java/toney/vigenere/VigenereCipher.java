package toney.vigenere;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * This is a Vigenere cipher implementation of the interface toney.vigenere.Cipher.
 * 
 * Assumption 1: The key.length is less than Integer.MAX_VALUE
 * Assumption 2: The key only contains characters in Char Set
 * Assumption 3: It might be only able to support plain text files as the Char Set only cover a small set of characters.
 */
public class VigenereCipher implements Cipher {

    protected final String charSet;
    protected final String key;

    /**
     * @param charSet This is a non-blank source character set. Any characters outside of the source character set will be copied as-is.
     * @param key This is a non-blank encryption key. It only contains characters in charSet.
     * @throws RuntimeException if either charSet or key is blank
     */
    public VigenereCipher(final String charSet, final String key) {
        this.charSet = charSet;
        this.key = key;
        validateConfig();
        init();
    }

    private int keyIndex;

    /**
     * This method will reset the key index for the encryption key. It should be invoked every time before a new encryption or decryption is executed.
     */
    private void init() {
        keyIndex = 0;
    }

    /**
     * A validation method to ensure the charSet and key are non-blank.
     * @throws RuntimeException if either charSet or key is blank
     */
    private void validateConfig() {
        if (charSet == null || charSet.isEmpty()) {
            throw new RuntimeException("Please provide a Char Set before using VigenereCipher.");
        }
        if (key == null || key.isEmpty()) {
            throw new RuntimeException("Please provide a Key before using VigenereCipher.");
        }
    }

    /**
     * 
     * @param charsToEncrypt An array or chars to encrypt
     * @param len The length of the charsToEncrypt. Only characters within the len will be processed.
     * @return The original charsToEncrypt array with encrypted characters.
     * @throws NullPointerException if charsToEncrypt is null
     */
    @Override
    public char[] encrypt(final char[] charsToEncrypt, final int len) {
        init();
        for (int i = 0; i < len; i++) {
            int col = this.charSet.indexOf(charsToEncrypt[i]);
            if (col >= 0) {
                int row = this.charSet.indexOf(this.key.charAt(this.keyIndex));
                int encryptedIndex = (col + row) % charSet.length();
                charsToEncrypt[i] = charSet.charAt(encryptedIndex);
                this.keyIndex = (this.keyIndex + 1) % this.key.length();
            }
        }
        return charsToEncrypt;
    }

    /**
     * 
     * @param charsToDecrypt An array or chars to decrypt
     * @param len The length of the charsToDecrypt. Only characters within the len will be processed.
     * @return The original charsToDecrypt array with decrypted characters.
     * @throws NullPointerException if charsToDecrypt is null
     */
    @Override
    public char[] decrypt(final char[] charsToDecrypt, final int len) {
        init();
        for (int i = 0; i < len; i++) {
            int col = this.charSet.indexOf(charsToDecrypt[i]);
            if (col >= 0) {
                int row = this.charSet.indexOf(this.key.charAt(this.keyIndex));
                int decryptedIndex;
                if (row > col) {
                    decryptedIndex = col + this.charSet.length() - row;
                } else {
                    decryptedIndex = col - row;
                }
                charsToDecrypt[i] = charSet.charAt(decryptedIndex);
                this.keyIndex = (this.keyIndex + 1) % this.key.length();
            }
        }
        return charsToDecrypt;
    }

    /**
     * 
     * @param input A non-null file to encrypt
     * @param output A non-null file to save the encrypted content
     * @throws IOException, NullPointerException if either input or output is null
     */
    @Override
    public void encrypt(final File input, final File output) throws IOException {
        try (
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(input)));
                FileWriter fileWriter = new FileWriter(output);) {
            init();
            char[] buffer = new char[1024 * 1024];
            int bufferLen;
            while ((bufferLen = bufferedReader.read(buffer, 0, buffer.length)) != -1) {
                encrypt(buffer, bufferLen);
                fileWriter.write(buffer, 0, bufferLen);
            }
        }
    }

    /**
     * 
     * @param input A non-null file to decrypt
     * @param output A non-null file to save the decrypted content
     * @throws IOException, NullPointerException if either input or output is null
     */
    @Override
    public void decrypt(final File input, final File output) throws IOException {
        try (
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(input)));
                FileWriter fileWriter = new FileWriter(output);) {
            init();
            char[] buffer = new char[1024 * 1024];
            int bufferLen;
            while ((bufferLen = bufferedReader.read(buffer, 0, buffer.length)) != -1) {
                buffer = decrypt(buffer, bufferLen);
                fileWriter.write(buffer, 0, bufferLen);
            }
        }
    }

    /**
     * 
     * @param _dir A non-blank directory to encrypt
     * @param maxDepth The depth of directory, please use Integer.MAX_VALUE if no arbitrarily depth limitation 
     * @param fileVisitOption Any options that the file tree travels.
     * @throws IOException if _dir is not a valid directory
     * There is no return. The encrypted directory will be _dir+".encrypted".
     */
    @Override
    public void encryptDir(final String _dir, final int maxDepth, final FileVisitOption... fileVisitOption) throws IOException {
        File dirFile = new File(_dir);
        String dir = dirFile.getAbsolutePath();
        File destDirFile = new File(dirFile.getParent(), dirFile.getName() + ".encrypted");
        String destDir = destDirFile.getAbsolutePath();
        try (Stream<Path> paths = Files.walk(Paths.get(dir), maxDepth, fileVisitOption);) {
            paths.forEach(p -> {
                File input = p.toFile();
                File output = new File(input.getAbsolutePath().replace(dir, destDir));
                if (input.isDirectory()) {
                    output.mkdirs();
                } else {
                    try {
                        encrypt(input, output);
                    } catch (IOException ex) {
                        Logger.getLogger(VigenereCipher.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            });
        }
    }

    /**
     * 
     * @param _dir A non-blank directory to decrypt
     * @param maxDepth The depth of directory, please use Integer.MAX_VALUE if no arbitrarily depth limitation 
     * @param fileVisitOption Any options that the file tree travels.
     * @throws IOException if _dir is not a valid directory
     * There is no return. The decrypted directory will be _dir+".decrypted". If _dir contains ".encrypted",  the ".encrypted" part will be deleted.
     */
    @Override
    public void decryptDir(final String _dir, final int maxDepth, final FileVisitOption... fileVisitOption) throws IOException {
        File dirFile = new File(_dir);
        String dir = dirFile.getAbsolutePath();
        File destDirFile = new File(dirFile.getParent(), dirFile.getName().replace(".encrypted", "") + ".decrypted");
        String destDir = destDirFile.getAbsolutePath();
        try (Stream<Path> paths = Files.walk(Paths.get(dir), maxDepth, fileVisitOption);) {
            init();
            paths.forEach(p -> {
                File input = p.toFile();
                File output = new File(input.getAbsolutePath().replace(dir, destDir));
                if (input.isDirectory()) {
                    output.mkdirs();
                } else {
                    try {
                        decrypt(input, output);
                    } catch (IOException ex) {
                        Logger.getLogger(VigenereCipher.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            });
        }
    }
}
