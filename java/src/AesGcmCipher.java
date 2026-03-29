import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class AesGcmCipher implements CipherStrategy {

    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE  = 12;
    private static final int TAG_SIZE = 128;

    private final SecretKey    key;
    private final SecureRandom rng = new SecureRandom();

    public AesGcmCipher() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(KEY_SIZE, rng);
        key = kg.generateKey();
    }

    @Override
    public byte[] encrypt(byte[] plaintext) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        rng.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, iv));
        byte[] enc = cipher.doFinal(plaintext);

        byte[] out = new byte[IV_SIZE + enc.length];
        System.arraycopy(iv,  0, out, 0,      IV_SIZE);
        System.arraycopy(enc, 0, out, IV_SIZE, enc.length);
        return out;
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) throws Exception {
        byte[] iv      = Arrays.copyOfRange(ciphertext, 0,       IV_SIZE);
        byte[] payload = Arrays.copyOfRange(ciphertext, IV_SIZE, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, iv));
        return cipher.doFinal(payload);
    }
}