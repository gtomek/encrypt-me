package uk.org.tomek.encryptme.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import android.content.Context;
import android.util.Log;

/**
 * Class used to encrypt/decrypt some String content on Android.
 * Based on 
 * http://android-developers.blogspot.co.uk/2013/02/using-cryptography-to-store-credentials.html
 * 
 * @author tomek
 *
 */
public class CryptoUtils {
	
	private static final String TAG = CryptoUtils.class.getSimpleName();
	private final Context mContext;

	private CryptoUtils(Context context) {
		mContext = context;
	}
	
	static CryptoUtils newInstance(Context context) {
		return new CryptoUtils(context);
	}

	public String encryptData(String clearText) {
		Cipher cipher = getCipher();
		if (cipher != null) {
			
		}
		return clearText;
		
	}
	
	public String decryptData(String encryptedText) {
		Cipher cipher = getCipher();
		if (cipher != null) {
			
		}
		return encryptedText;
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
	 * GEnerates secret key without PIN code.
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static SecretKey generateKey() throws NoSuchAlgorithmException {
	    // Generate a 256-bit key
	    final int outputKeyLength = 256;

	    SecureRandom secureRandom = new SecureRandom();
	    // Do *not* seed secureRandom! Automatically seeded from system entropy.
	    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	    keyGenerator.init(outputKeyLength, secureRandom);
	    SecretKey key = keyGenerator.generateKey();
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
