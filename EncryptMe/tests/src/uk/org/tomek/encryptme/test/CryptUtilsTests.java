package uk.org.tomek.encryptme.test;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import uk.org.tomek.encryptme.crypto.CryptoUtils;
import uk.org.tomek.encryptme.crypto.KeyFactory;
import android.test.AndroidTestCase;
import android.util.Log;


public class CryptUtilsTests extends AndroidTestCase {

	private static final byte[] INPUT_DATA_BYTES = {(byte) 0x01, (byte) 0x02, (byte) 0x03,
		(byte) 0x04,(byte) 0x05,(byte) 0x06,(byte) 0x07,(byte) 0x08,(byte) 0x09,(byte) 0x0A,
		(byte) 0x0B,(byte) 0x0C,(byte) 0x0D,(byte) 0x0E,(byte) 0x0F,(byte) 0x00};
	private String TAG = CryptUtilsTests.class.getSimpleName();
	private KeyFactory mKeyFactory;
	
	protected void setUp() throws Exception {
		super.setUp();
		mKeyFactory = KeyFactory.newInstance(getContext());
	}

	public void testEncryptDataBytes() {
		CryptoUtils cryptoUtils = CryptoUtils.newInstance(mKeyFactory);
		byte[] encryptedDataBytes = cryptoUtils.encryptData(INPUT_DATA_BYTES);
		Log.d(TAG, String.format("Encrypted bytes:%s", encryptedDataBytes));
		byte[] decryptedDataBytes = cryptoUtils.decryptData(encryptedDataBytes);
		assertTrue(Arrays.equals(INPUT_DATA_BYTES, decryptedDataBytes));
	}

	public void testEncryptDataStrings() throws UnsupportedEncodingException {
		String inputString = new String(INPUT_DATA_BYTES, CryptoUtils.DEFAULT_CHARSET);
		CryptoUtils cryptoUtils = CryptoUtils.newInstance(mKeyFactory);
		byte[] encryptedData = cryptoUtils.encryptData(inputString);
		Log.d(TAG, String.format("Encrypted data:%s", encryptedData));
		byte[] decryptedData = cryptoUtils.decryptData(encryptedData);
		assertTrue(Arrays.equals(inputString.getBytes(CryptoUtils.DEFAULT_CHARSET), decryptedData));
	}

}
