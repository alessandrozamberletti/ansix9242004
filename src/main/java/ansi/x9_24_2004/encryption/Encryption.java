package ansi.x9_24_2004.encryption;

import ansi.x9_24_2004.utils.CustomBitSet;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public interface Encryption {

    default byte[] encrypt(final CustomBitSet key,
                           final byte[] data,
                           final boolean padding) {
        try {
            final SecretKey secretKey = getEncryptionKey(key);
            final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
            final Cipher cipher = getCipher(padding);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e.getMessage());
        }
    }

    default byte[] encrypt(final CustomBitSet key,
                           final byte[] data) {
        return encrypt(key, data, false);
    }

    default byte[] decrypt(final CustomBitSet key,
                           final byte[] data,
                           final boolean padding) {
        try {
            final SecretKey secretKey = getEncryptionKey(key);
            final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
            final Cipher cipher = getCipher(padding);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e.getMessage());
        }
    }

    default byte[] decrypt(final CustomBitSet key,
                           final byte[] data) {
        return decrypt(key, data, false);
    }

    SecretKey getEncryptionKey(final CustomBitSet key);

    String padding();

    String noPadding();

    default Cipher getCipher(final boolean padding) {
        try {
            return Cipher.getInstance(padding ? padding() : noPadding());
        } catch (Exception e) {
            throw new IllegalStateException(e.getMessage());
        }
    }

}
