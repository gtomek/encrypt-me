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
import javax.crypto.spec.SecretKeySpec;

import uk.org.tomek.encryptme.helpers.HexStringHelper;
import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;

/**
 * Creates encryption key used to encrypt/ decrypt the data.
 * 
 * @author Tomasz Giszczak
 * 
 */
public final class KeyFactory {

	// logger TAG
	private static final String TAG = "KeyFactory";
	private static final String AES = "AES";
	private static final String KEY_PREFS = "key_prefs";
	private static final String ENCRYPTION_KEY = "encryption_key";
	private final SecretKey mKeyNoPin;
	private final SharedPreferences mSharedPreferences;

	// private constructor (please use newIntance() instead)
	private KeyFactory(Context context) {
		if (context == null) {
			throw new IllegalArgumentException();
		}
		mSharedPreferences = context.getSharedPreferences(KEY_PREFS, Context.MODE_PRIVATE);
		// try to read saved key
		SecretKey savedKey = readSavedKey();
		if (savedKey == null) {
			// no saved key available, therefore create a new one
			mKeyNoPin = generateKey();
			Log.d(TAG, String.format("Created new key=%s", mKeyNoPin.getEncoded()));
		} else {
			mKeyNoPin = savedKey;
			Log.d(TAG, String.format("Using saved key=%s", mKeyNoPin.getEncoded()));
		}
	}

	/**
	 * Creates new instance of {@link KeyFactory}.
	 * 
	 * @return {@link KeyFactory}
	 */
	public static KeyFactory newInstance(Context context) {
		return new KeyFactory(context);
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

		// taking into account the change in KITKAT
		// see
		// http://android-developers.blogspot.co.uk/2013/12/changes-to-secretkeyfactory-api-in.html
		SecretKeyFactory secretKeyFactory = null;
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
			// Use compatibility key factory -- only uses lower 8-bits of passphrase chars
			secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1And8bit");
		} else {
			// Traditional key factory. Will use lower 8-bits of passphrase chars on
			// older Android versions (API level 18 and lower) and all available bits
			// on KitKat and newer (API level 19 and higher).
			secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		}
		KeySpec keySpec = new PBEKeySpec(passphraseOrPin, salt, iterations, outputKeyLength);
		SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
		return secretKey;
	}

	/**
	 * Store current key in persistent storage.
	 */
	@TargetApi(Build.VERSION_CODES.GINGERBREAD)
	public void saveKey() {
		Editor preferncesEditor = mSharedPreferences.edit();
		byte[] encodedKeyBytes = mKeyNoPin.getEncoded();
		Log.d(TAG,
				String.format("Saving binary key:%s", HexStringHelper.hexEncode(encodedKeyBytes)));
		preferncesEditor.putString(ENCRYPTION_KEY, new String(encodedKeyBytes,
				CryptoUtils.DEFAULT_CHARSET));
		preferncesEditor.commit();
	}

	/*
	 * Reads and recreates previously saved key.
	 */
	@TargetApi(Build.VERSION_CODES.GINGERBREAD)
	private SecretKey readSavedKey() {
		String keySring = mSharedPreferences.getString(ENCRYPTION_KEY, null);
		if (TextUtils.isEmpty(keySring)) {
			return null;
		} else {
			Log.d(TAG, String.format("Got String key:%s", keySring));
			SecretKeySpec secretKeySpec = new SecretKeySpec(
					keySring.getBytes(CryptoUtils.DEFAULT_CHARSET), AES);
			Log.d(TAG,
					String.format("Retrieved binary key:%s",
							HexStringHelper.hexEncode(secretKeySpec.getEncoded())));
			return secretKeySpec;
		}
	}
}
