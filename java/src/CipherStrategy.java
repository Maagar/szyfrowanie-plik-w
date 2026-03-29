public interface CipherStrategy {
    byte[] encrypt(byte[] plaintext) throws Exception;
    byte[] decrypt(byte[] ciphertext) throws Exception;
}