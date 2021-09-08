package toney.vigenere;

import java.io.IOException;

public class App {

    public static final String CIPHER_CHAR_SET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \t\n\r~!@#$%^&*()_+-=[]\\{}|;':\",./<>?";

    public static void main(String args[]) throws IOException {
        if (args.length != 3) {
            System.out.println("Exact 3 parameters required - [action] [key] [target]");
            System.exit(1);
        }
        
        String action, key, target;
        action = args[0];
        key = args[1];
        target = args[2];
        
        VigenereCipher cipher = new VigenereCipher(CIPHER_CHAR_SET, key);
        
        if ("encrypt".equalsIgnoreCase(action)) {
            System.out.println("encrypt [" + key + "], [" + target + "]");
            char[] result = cipher.encrypt(target.toCharArray(), target.length());
            System.out.println(new String(result));
        } else if ("decrypt".equalsIgnoreCase(action)) {
            System.out.println("decrypt [" + key + "], [" + target + "]");
            char[] result = cipher.decrypt(target.toCharArray(), target.length());
            System.out.println(new String(result));
        } else if ("encryptDir".equalsIgnoreCase(action)) {
            System.out.println("encryptDir [" + key + "], [" + target + "]");
            cipher.encryptDir(target, Integer.MAX_VALUE);
            System.out.println("encryptDir [" + key + "], [" + target + "] DONE");
        } else if ("decryptDir".equalsIgnoreCase(action)) {
            System.out.println("decryptDir [" + key + "], [" + target + "]");
            cipher.decryptDir(target, Integer.MAX_VALUE);
            System.out.println("decryptDir [" + key + "], [" + target + "] DONE");
        } else {
            System.out.println("action [" + action + "] not implemented");
        }

    }
}
