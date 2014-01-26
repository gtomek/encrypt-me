package uk.org.tomek.encryptme.test;
import uk.org.tomek.encryptme.crypto.CryptoUtils;
import android.test.AndroidTestCase;
import android.util.Log;


public class CryptUtilsTests extends AndroidTestCase {

	private static final String INPUT_DATA = "testStringData12";
	private String TAG = CryptUtilsTests.class.getSimpleName();
	
	protected void setUp() throws Exception {
		super.setUp();
	}

	public void testEncryptData() {
		CryptoUtils cryptoUtils = CryptoUtils.newInstance();
		String encryptedData = cryptoUtils.encryptData(INPUT_DATA);
		Log.d(TAG, String.format("Encrypted bytes:%s", encryptedData));
		String decryptedData = cryptoUtils.decryptData(encryptedData);
		assertEquals(INPUT_DATA, decryptedData);
	}

	public void testDecryptData() {
		fail("Not yet implemented");
	}

}
