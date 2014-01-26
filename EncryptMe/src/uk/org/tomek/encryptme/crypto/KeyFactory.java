package uk.org.tomek.encryptme.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import android.util.Log;

/**
 * Creates encryption key used to encrypt/ decrypt the data. 
 * 
 * @author Tomasz Giszczak
 *
 */
public final  class KeyFactory {

	// logger TAG
	private static final String TAG = "KeyFactory";
	private static final String AES = "AES";
	private final SecretKey mKeyNoPin;

	// private constructor (please use newIntance() instead)
	private KeyFactory() {
		mKeyNoPin = generateKey();
		Log.d(TAG, String.format("Created new key=%s", mKeyNoPin.getEncoded()));
	}

	/**
	 * Creates new instance of {@link KeyFactory}.
	 * 
	 * @return {@link KeyFactory}
	 */
	public static KeyFactory newInstance() {
		return new KeyFactory();
	}
	
	/**
	 * Returns default key created during class initialisation.
	 * 
	 * @return default secret key
	 */
	public SecretKey getKeyNoPin() {
		return mKeyNoPin;
	}
	
	/**
	 * Generates secret key without PIN code.
	 * 
	 * @return a key or null
	 */
	public static SecretKey generateKey() {
		// Generate a 128-bit key
		int outputKeyLength = 128;
		
		// check max supported key length for AES
		try {
			int maxAllowedKeyLength = Cipher.getMaxAllowedKeyLength(AES);
			Log.d(TAG, String.format("maxAllowedKeyLength for AES=%d", maxAllowedKeyLength));
			// set the output key length to 256 if supported
			if (maxAllowedKeyLength >= 256) {
				outputKeyLength = 256;
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		

		SecureRandom secureRandom = new SecureRandom();
		// Do *not* seed secureRandom! Automatically seeded from system entropy.
		KeyGenerator keyGenerator;
		SecretKey key = null;
		try {
			keyGenerator = KeyGenerator.getInstance(AES);
			keyGenerator.init(outputKeyLength, secureRandom);
			key = keyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			Log.d(TAG, "Impossible to create encryption key" + e.getClass().getSimpleName());
			e.printStackTrace();
		}
		return key;
	}

	/**
	 * Generates secret code with PIN code used as an input parameter.
	 * 
	 * @param passphraseOrPin
	 * @param salt
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static SecretKey generateKey(char[] passphraseOrPin, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		// Number of PBKDF2 hardening rounds to use. Larger values increase
		// computation time. You should select a value that causes computation
		// to take >100ms.
		final int iterations = 1000;

		// Generate a 128-bit key
		final int outputKeyLength = 128;

		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec keySpec = new PBEKeySpec(passphraseOrPin, salt, iterations, outputKeyLength);
		SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
		return secretKey;
	}
}
