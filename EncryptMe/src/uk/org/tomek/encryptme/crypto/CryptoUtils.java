package uk.org.tomek.encryptme.crypto;

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

import android.util.Log;

/**
 * Class used to encrypt/decrypt some String content on Android.
 * Based on 
 * http://android-developers.blogspot.co.uk/2013/02/using-cryptography-to-store-credentials.html
 * 
 * @author Tomek Giszczak
 *
 */
public class CryptoUtils {
	
	private static final String TAG = CryptoUtils.class.getSimpleName();
	private static final String IV_BYTES = "!dsf345fdssd5432"; 
	private final SecretKey mKey;
	

	private CryptoUtils() {
		mKey = generateKey();
	}
	
	public static CryptoUtils newInstance() {
		return new CryptoUtils();
	}

	public String encryptData(String clearText) {
		Cipher cipher = getCipher();
		String outputString = null;
		
		if (cipher != null && mKey != null) {
			try {
				IvParameterSpec ivSpec = new IvParameterSpec(IV_BYTES.getBytes());
				cipher.init(Cipher.ENCRYPT_MODE, mKey, ivSpec);
				byte[] inputBytes = clearText.getBytes();
				byte[] outputBytes = cipher.doFinal(inputBytes);
				outputString = new String(outputBytes);
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
		return outputString;
	}
	
	public String decryptData(String encryptedText) {
		Cipher cipher = getCipher();
		String outputString = null;
		IvParameterSpec ivSpec = new IvParameterSpec(IV_BYTES.getBytes());
		
		if (cipher != null && mKey != null) {
			try {
				cipher.init(Cipher.DECRYPT_MODE, mKey, ivSpec);
				byte[] inputBytes = encryptedText.getBytes();
				byte[] outputBytes = cipher.doFinal(inputBytes);
				outputString = new String(outputBytes);
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
		return outputString;
	}
	
	/**
	 * Returns Cipher instance.
	 * @return
	 */
	private Cipher getCipher() {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			Log.d(TAG, "Impossible to get Cipher instancem" + e.getClass().getSimpleName());
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			Log.d(TAG, "Impossible to get Cipher instancem" + e.getClass().getSimpleName());
			e.printStackTrace();
		}
		return cipher;
	}
	
	/**
	 * Generates secret key without PIN code.
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
	 * @param passphraseOrPin
	 * @param salt
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static SecretKey generateKey(char[] passphraseOrPin, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
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
	
}
