package ansix9242004.dukpt;

import ansix9242004.encryption.Des;
import ansix9242004.encryption.TripleDes;
import ansix9242004.utils.BitSet;
import ansix9242004.utils.ByteArrayUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * <p>The Dukpt class acts a name-space for the Derived
 * Unique Key-Per-Transaction (Dukpt) standard using the
 * Data Encryption Standard, DES, (often referred to in practice as
 * "DEA", for Data Encryption Algorithm).
 *
 * <p>The functions provided attempt to aid a user in performing
 * encryption, decryption, and possibly more complex operations
 * using these.
 *
 * <p>There is also a set of conversion methods to hopefully make
 * the class even easier to interface with.  Many of these involve
 * the BitSet wrapper of java.util.BitSet which was designed to have
 * a proper "bitSize()" function as Java's BitSet does not have a method
 * that returns the constructed length of the BitSet, only its actual
 * size in memory and its "logical" size (1 + the index of the left-most 1).
 *
 * <p>To further augment to the security of Dukpt, two "oblivate()" methods are
 * included, one for the extended BitSet and one for byte arrays.  These
 * overwrite their respective arguments with random data as supplied by
 * java.secruty.SecureRandom to ensure that their randomness is
 * cryptographically strong.  The default number of overwrites is specified by
 * the static constant NUM_OVERWRITES but the user can supply a different number
 * should they desire the option.
 *
 * @author Software Verde: Andrew Groot
 * @author Software Verde: Josh Green
 */
public class Dukpt {

	private final Des des;
	private final TripleDes tripleDes;

	Dukpt(final Des des, final TripleDes tripleDes) {
		this.des = des;
		this.tripleDes = tripleDes;
	}

	BitSet computeKey(final BitSet bdk, final BitSet ksn, final Mask mask) {
		BitSet ipek = getIpek(bdk, ksn);
		BitSet key = getCurrentKey(ipek, ksn);

		key.xor(mask.value());

		return key;
	}

	BitSet getIpek(final BitSet key, final BitSet ksn) {
		byte[][] ipek = new byte[2][];
		BitSet keyRegister = key.get(0, key.bitSize());
		BitSet data = ksn.get(0, ksn.bitSize());
		data.clear(59, 80);

		ipek[0] = tripleDes.encrypt(keyRegister, BitSet.toByteArray(data.get(0, 64)), false);

		keyRegister.xor(Mask.KEY_REGISTER_BITMASK.value());
		ipek[1] = tripleDes.encrypt(keyRegister, BitSet.toByteArray(data.get(0, 64)), false);

		try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
			byteArrayOutputStream.write(ipek[0]);
			byteArrayOutputStream.write(ipek[1]);

			return ByteArrayUtils.toBitSet(byteArrayOutputStream.toByteArray());
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	BitSet getCurrentKey(final BitSet ipek, final BitSet ksn) {
		BitSet key = ipek.get(0, ipek.bitSize());
		BitSet counter = ksn.get(0, ksn.bitSize());
		counter.clear(59, ksn.bitSize());

		for (int i = 59; i < ksn.bitSize(); i++) {
			if (ksn.get(i)) {
				counter.set(i);
				key = nonReversibleKeyGenerationProcess(key, counter.get(16, 80), Mask.KEY_REGISTER_BITMASK.value());
			}
		}

		return key;
	}

	BitSet nonReversibleKeyGenerationProcess(final BitSet pKey, final BitSet data, final BitSet keyRegisterBitmask) {
		BitSet keyReg = pKey.get(0, pKey.bitSize());
		BitSet reg1 = data.get(0, data.bitSize());
		// step 1: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-2.
		BitSet reg2 = reg1.get(0, 64); // reg2 is being used like a temp here
		reg2.xor(keyReg.get(64, 128));   // and here, too, kind of
		// step 2: Crypto Register-2 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-2
		reg2 = ByteArrayUtils.toBitSet(des.encrypt(keyReg.get(0, 64), BitSet.toByteArray(reg2), false));
		// step 3: Crypto Register-2 XORed with the right half of the Key Register goes to Crypto Register-2
		reg2.xor(keyReg.get(64, 128));
		// done messing with reg2

		// step 4: XOR the Key Register with hexadecimal C0C0 C0C0 0000 0000 C0C0 C0C0 0000 0000
		keyReg.xor(keyRegisterBitmask);
		// step 5: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
		reg1.xor(keyReg.get(64, 128));
		// step 6: Crypto Register-1 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-1
		reg1 = ByteArrayUtils.toBitSet(des.encrypt(keyReg.get(0, 64), BitSet.toByteArray(reg1), false));
		// step 7: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
		reg1.xor(keyReg.get(64, 128));
		// done

		byte[] reg1b = BitSet.toByteArray(reg1);
		byte[] reg2b = BitSet.toByteArray(reg2);
		byte[] key = ByteArrayUtils.concat(reg1b, reg2b);

		return ByteArrayUtils.toBitSet(key);
	}

	/*
	byte[] toDataKey(final byte[] derivedKey) throws Exception {
		if (derivedKey == null || derivedKey.length != 16) {
			throw new IllegalArgumentException("Invalid key provided: " + (derivedKey == null ? "null" : "length " + derivedKey.length));
		}

		byte[] left = Arrays.copyOfRange(derivedKey, 0, 8);
		byte[] right = Arrays.copyOfRange(derivedKey, 8, 16);

		byte[] leftEncrypted = tripleDes.encrypt(derivedKey, left, false);
		byte[] rightEncrypted = tripleDes.encrypt(derivedKey, right, false);

		return ByteArrayUtils.concat(leftEncrypted, rightEncrypted);
	}
	 */

}
