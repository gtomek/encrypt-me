package uk.org.tomek.encryptme.crypto;

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

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
	public static final String LATIN_FORMAT = "Latin-1";
	public static final Charset DEFAULT_CHARSET = Charset.forName(LATIN_FORMAT);

	private static final String TAG = CryptoUtils.class.getSimpleName();
//	private static final String CIPHER_ALGO = "AES/CBC/PKCS5Padding";
	private static final String CIPHER_ALGO = "PBEWITHMD5AND256BITAES-CBC-OPENSSL"; 
	private static final byte[] IV_BYTES = { (byte) 0xf8, (byte) 0x9f, (byte) 0x0a, (byte) 0x2b,
			(byte) 0x9b, (byte) 0x5b, (byte) 0x11, (byte) 0xad, (byte) 0x61, (byte) 0x19,
			(byte) 0xe9, (byte) 0xb6, (byte) 0x9f, (byte) 0xda, (byte) 0xf1, (byte) 0x3f };
	private static final IvParameterSpec IV_PARAMS_SPEC = new IvParameterSpec(IV_BYTES);
	private final KeyFactory mKeyFactory;
	private Cipher sCipher;

	private CryptoUtils(KeyFactory keyFactory) {
		mKeyFactory = keyFactory;
	}

	/**
	 * Applies PRNGFixes and creates new instance of {@link CryptoUtils}.
	 * 
	 * @return {@link CryptoUtils}
	 */
	public static CryptoUtils newInstance(KeyFactory keyFactory) {
		// apply PRNG fixes
		PRNGFixes.apply();
		return new CryptoUtils(keyFactory);
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

		if (cipher != null && mKeyFactory != null) {
			
			try {
				SecretKey keyNoPin = mKeyFactory.getKeyNoPin();
				Log.d(TAG, String.format("Using the key size:%d, key:%s", keyNoPin.getEncoded().length, 
						HexStringHelper.hexEncode(keyNoPin.getEncoded())));
				cipher.init(Cipher.ENCRYPT_MODE, keyNoPin, IV_PARAMS_SPEC);
				byte[] outputBytes = cipher.doFinal(inputBytes);
				Log.d(TAG, String.format("Encrypted data:%s",  
						HexStringHelper.hexEncode(outputBytes)));
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
	public byte[] encryptData(String inputText) {
		if (!TextUtils.isEmpty(inputText)) {
			byte[] encryptedData = encryptData(inputText.getBytes(DEFAULT_CHARSET));
			return encryptedData;
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

		if (cipher != null && mKeyFactory != null) {
			try {
				SecretKey keyNoPin = mKeyFactory.getKeyNoPin();
				Log.d(TAG, String.format("Using the key size:%d, key:%s", keyNoPin.getEncoded().length, 
						HexStringHelper.hexEncode(keyNoPin.getEncoded())));
				cipher.init(Cipher.DECRYPT_MODE, keyNoPin, IV_PARAMS_SPEC);
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
	 * Returns crypto key. 
	 */
	public SecretKey getKey() {
		return mKeyFactory.getKeyNoPin();
	}
	
	/**
	 * Returns currently used ciphering algo.
	 * @return
	 */
	public String getCipherAlgo() {
		return CIPHER_ALGO;
	}
}
