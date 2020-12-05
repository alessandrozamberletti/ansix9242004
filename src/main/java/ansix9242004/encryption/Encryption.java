package ansix9242004.encryption;

import ansix9242004.utils.BitSet;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public interface Encryption {

    default byte[] encrypt(BitSet key, byte[] data, boolean padding) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        final SecretKey secretKey = getEncryptionKey(key);
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        final Cipher cipher = getCipher(padding);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        return cipher.doFinal(data);
    }

    default byte[] decrypt(BitSet key, byte[] data, boolean padding) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        final SecretKey secretKey = getEncryptionKey(key);
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        final Cipher cipher = getCipher(padding);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        return cipher.doFinal(data);
    }

    SecretKey getEncryptionKey(BitSet key) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException;

    String padding();

    String noPadding();

    default Cipher getCipher(boolean padding) throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance(padding ? padding() : noPadding());
    }

}
