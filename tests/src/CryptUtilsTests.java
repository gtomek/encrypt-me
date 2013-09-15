import uk.org.tomek.encryptme.crypto.CryptoUtils;
import android.test.AndroidTestCase;
import android.util.Log;


public class CryptUtilsTests extends AndroidTestCase {

	private static final String INPUT_DATA = "testStringData";
	private String TAG = CryptUtilsTests.class.getSimpleName();
	
	protected void setUp() throws Exception {
		super.setUp();
	}

	public void testEncryptData() {
		CryptoUtils cryptoUtils = CryptoUtils.newInstance();
		Log.d(TAG, String.format("Input data:%s", INPUT_DATA));
		String encryptedData = cryptoUtils.encryptData(INPUT_DATA);
		Log.d(TAG, String.format("Encrypted data:%s", encryptedData));
		String decryptedData = cryptoUtils.decryptData(encryptedData);
		Log.d(TAG, String.format("Decrypted data:%s", decryptedData));
		assertEquals(INPUT_DATA, decryptedData);
	}

	public void testDecryptData() {
		fail("Not yet implemented");
	}

}
