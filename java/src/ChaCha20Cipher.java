import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class ChaCha20Cipher implements CipherStrategy {

    private static final int KEY_SIZE   = 256;
    private static final int NONCE_SIZE = 12;

    private final SecretKey    key;
    private final SecureRandom rng = new SecureRandom();

    public ChaCha20Cipher() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("ChaCha20");
        kg.init(KEY_SIZE, rng);
        key = kg.generateKey();
    }

    @Override
    public byte[] encrypt(byte[] plaintext) throws Exception {
        byte[] nonce = new byte[NONCE_SIZE];
        rng.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
        byte[] enc = cipher.doFinal(plaintext);

        byte[] out = new byte[NONCE_SIZE + enc.length];
        System.arraycopy(nonce, 0, out, 0,          NONCE_SIZE);
        System.arraycopy(enc,   0, out, NONCE_SIZE, enc.length);
        return out;
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) throws Exception {
        byte[] nonce   = Arrays.copyOfRange(ciphertext, 0,          NONCE_SIZE);
        byte[] payload = Arrays.copyOfRange(ciphertext, NONCE_SIZE, ciphertext.length);

        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
        return cipher.doFinal(payload);
    }
}