package toney.vigenere;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitOption;

/**
 * 
 * This is a cipher interface that provides encryption and decryption of arrays, files and directories.
 */
public interface Cipher {

    /**
     * 
     * @param charsToEncrypt An array or chars to encrypt
     * @param len The length of the charsToEncrypt. Only characters within the len will be processed.
     * @return The original charsToEncrypt array with encrypted characters.
     * @throws NullPointerException if charsToEncrypt is null
     */
    public char[] encrypt(final char[] charsToEncrypt, final int len);
    
    /**
     * 
     * @param charsToDecrypt An array or chars to decrypt
     * @param len The length of the charsToDecrypt. Only characters within the len will be processed.
     * @return The original charsToDecrypt array with decrypted characters.
     * @throws NullPointerException if charsToDecrypt is null
     */
    public char[] decrypt(final char[] charsToDecrypt, final int len);
    
    /**
     * 
     * @param input A non-null file to encrypt
     * @param output A non-null file to save the encrypted content
     * @throws IOException, NullPointerException if either input or output is null
     */
    public void encrypt(final File input, final File output) throws IOException;
    
    /**
     * 
     * @param input A non-null file to decrypt
     * @param output A non-null file to save the decrypted content
     * @throws IOException, NullPointerException if either input or output is null
     */
    public void decrypt(final File input, final File output) throws IOException;
    
    /**
     * 
     * @param dirToEncrypt A non-blank directory to encrypt
     * @param maxDepth The depth of directory, please use Integer.MAX_VALUE if no arbitrarily depth limitation 
     * @param fileVisitOption Any options that the file tree travels.
     * @throws IOException if dirToEncrypt is not a valid directory
     * There is no return. The encrypted directory will be dirToEncrypt+".encrypted".
     */
    public void encryptDir(final String dirToEncrypt, final int maxDepth, final FileVisitOption... fileVisitOption) throws IOException;
    
    /**
     * 
     * @param dirToDecrypt A non-blank directory to decrypt
     * @param maxDepth The depth of directory, please use Integer.MAX_VALUE if no arbitrarily depth limitation 
     * @param fileVisitOption Any options that the file tree travels.
     * @throws IOException if dirToDecrypt is not a valid directory
     * There is no return. The decrypted directory will be dirToDecrypt+".decrypted". If dirToDecrypt contains ".encrypted",  the ".encrypted" part will be deleted.
     */
    public void decryptDir(final String dirToDecrypt, final int maxDepth, final FileVisitOption... fileVisitOption) throws IOException;
}
