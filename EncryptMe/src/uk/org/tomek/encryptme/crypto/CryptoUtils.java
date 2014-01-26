package uk.org.tomek.encryptme.crypto;

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import uk.org.tomek.encryptme.helpers.HexStringHelper;
import android.annotation.TargetApi;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;

/**
 * Class used to encrypt/decrypt some String content on Android. Based on
 * http://android-developers.blogspot.co.uk/2013/02/using-cryptography-to-store-credentials.html
 * 
 * @author Tomek Giszczak
 * 
 */
public class CryptoUtils {

	private static final String TAG = CryptoUtils.class.getSimpleName();
	private static final String UNICODE_FORMAT = "UTF-8";
	private static final Charset DEFAULT_CHARSET = Charset.forName(UNICODE_FORMAT);
//	private static final String CIPHER_ALGO = "AES/CBC/PKCS5Padding";
	private static final String CIPHER_ALGO = "PBEWITHMD5AND256BITAES-CBC-OPENSSL"; 
	private static final byte[] IV_BYTES = { (byte) 0xf8, (byte) 0x9f, (byte) 0x0a, (byte) 0x2b,
			(byte) 0x9b, (byte) 0x5b, (byte) 0x11, (byte) 0xad, (byte) 0x61, (byte) 0x19,
			(byte) 0xe9, (byte) 0xb6, (byte) 0x9f, (byte) 0xda, (byte) 0xf1, (byte) 0x3f };
	private static final IvParameterSpec IV_PARAMS_SPEC = new IvParameterSpec(IV_BYTES);
	private final SecretKey mKey;
	private Cipher sCipher;

	private CryptoUtils() {
		mKey = generateKey();
	}

	/**
	 * Applies PRNGFixes and creates new instance of {@link CryptoUtils}.
	 * 
	 * @return {@link CryptoUtils}
	 */
	public static CryptoUtils newInstance() {
		// apply PRNG fixes
		PRNGFixes.apply();
		return new CryptoUtils();
	}

	/**
	 * Encrypts data.
	 * 
	 * @param inputBytes
	 * @return
	 */
	public byte[] encryptData(byte[] inputBytes) {
		Log.d(TAG, String.format("encryptData called with size:%d, data:%s", inputBytes.length, 
				HexStringHelper.hexEncode(inputBytes)));
		Cipher cipher = getCipher();

		if (cipher != null && mKey != null) {
			try {
				Log.d(TAG, String.format("Using the key size:%d, key:%s", mKey.getEncoded().length, 
						HexStringHelper.hexEncode(mKey.getEncoded())));
				cipher.init(Cipher.ENCRYPT_MODE, mKey, IV_PARAMS_SPEC);
				byte[] outputBytes = cipher.doFinal(inputBytes);
				return outputBytes;
			} catch (InvalidKeyException e) {
				Log.d(TAG, "Impossible encrypt," + e.getClass().getSimpleName());
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				Log.d(TAG, "Impossible encrypt," + e.getClass().getSimpleName());
				e.printStackTrace();
			} catch (BadPaddingException e) {
				Log.d(TAG, "Impossible encrypt," + e.getClass().getSimpleName());
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				Log.d(TAG, "Impossible encrypt," + e.getClass().getSimpleName());
				e.printStackTrace();
			} 
		}
		return null;
	}

	/**
	 * Encryption method taking and returning {@link String} as input.
	 * 
	 * @param inputText
	 * @return
	 */
	@TargetApi(Build.VERSION_CODES.GINGERBREAD)
	public String encryptData(String inputText) {
		if (!TextUtils.isEmpty(inputText)) {
			byte[] encryptedData = encryptData(inputText.getBytes(DEFAULT_CHARSET));
			return new String(encryptedData);
		}
		return null;
	}

	/**
	 * Decrypts data.
	 * 
	 * @param encryptedText
	 * @return
	 */
	public byte[] decryptData(byte[] inputBytes) {
		Log.d(TAG, String.format("decryptData called with size:%d, data:%s", inputBytes.length, HexStringHelper.hexEncode(inputBytes)));
		Cipher cipher = getCipher();

		if (cipher != null && mKey != null) {
			try {
				Log.d(TAG, String.format("Using the key size:%d, key:%s", mKey.getEncoded().length, 
						HexStringHelper.hexEncode(mKey.getEncoded())));
				cipher.init(Cipher.DECRYPT_MODE, mKey, IV_PARAMS_SPEC);
				byte[] outputBytes = cipher.doFinal(inputBytes);
				return outputBytes;
			} catch (InvalidKeyException e) {
				Log.d(TAG, "Impossible decrypt," + e.getClass().getSimpleName());
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				Log.d(TAG, "Impossible decrypt," + e.getClass().getSimpleName());
				e.printStackTrace();
			} catch (BadPaddingException e) {
				Log.d(TAG, "Impossible decrypt," + e.getClass().getSimpleName());
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				Log.d(TAG, "Impossible decrypt," + e.getClass().getSimpleName());
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * Decryption method taking and returning {@link String} as input.
	 * 
	 * @param encryptedInputText
	 * @return
	 */
	@TargetApi(Build.VERSION_CODES.GINGERBREAD)
	public String decryptData(String encryptedInputText) {
		if (!TextUtils.isEmpty(encryptedInputText)) {
			byte[] decryptedData = decryptData(encryptedInputText.getBytes(DEFAULT_CHARSET));
			if (decryptedData != null) {
				return new String(decryptedData);
			}
		} else {
			Log.e(TAG,"Cannot decrypt an empty encryptedInputText!");
		}
		return null;
	}

	/**
	 * Returns Cipher instance.
	 * 
	 * @return
	 */
	private Cipher getCipher() {
//		final String CIPHER_PROVIDER = "BC";
		if (sCipher == null) {
			try {
//				sCipher = Cipher.getInstance(CIPHER_ALGO, CIPHER_PROVIDER);
				sCipher = Cipher.getInstance(CIPHER_ALGO);
			} catch (NoSuchAlgorithmException e) {
				Log.d(TAG, "Impossible to get Cipher instancem" + e.getClass().getSimpleName());
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				Log.d(TAG, "Impossible to get Cipher instancem" + e.getClass().getSimpleName());
				e.printStackTrace();
			} 
		}
		return sCipher;
	}

	/**
	 * Generates secret key without PIN code.
	 * 
	 * @return a key or null
	 */
	public static SecretKey generateKey() {
		// Generate a 256-bit key
		final int outputKeyLength = 256;

		SecureRandom secureRandom = new SecureRandom();
		// Do *not* seed secureRandom! Automatically seeded from system entropy.
		KeyGenerator keyGenerator;
		SecretKey key = null;
		try {
			keyGenerator = KeyGenerator.getInstance("AES");
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

		// Generate a 256-bit key
		final int outputKeyLength = 256;

		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec keySpec = new PBEKeySpec(passphraseOrPin, salt, iterations, outputKeyLength);
		SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
		return secretKey;
	}

	/**
	 * Returns crypto key. 
	 */
	public SecretKey getKey() {
		return mKey;
	}
	
	/**
	 * Returns currently used ciphering algo.
	 * @return
	 */
	public String getCipherAlgo() {
		return CIPHER_ALGO;
	}
}
