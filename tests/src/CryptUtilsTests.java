import uk.org.tomek.encryptme.crypto.CryptoUtils;
import uk.org.tomek.encryptme.helpers.HexStringHelper;
import android.test.AndroidTestCase;
import android.util.Log;


public class CryptUtilsTests extends AndroidTestCase {

	private static final String INPUT_DATA = "ABCDEFabcdef1234";
	private String TAG = CryptUtilsTests.class.getSimpleName();
	
	protected void setUp() throws Exception {
		super.setUp();
	}

	public void testEncryptData() {
		CryptoUtils cryptoUtils = CryptoUtils.newInstance();
		Log.d(TAG, String.format("Input data:%s", HexStringHelper.hexEncode(INPUT_DATA.getBytes())));
		byte[] encryptedData = cryptoUtils.encryptData(INPUT_DATA.getBytes());
		Log.d(TAG, String.format("Encrypted data:%s", HexStringHelper.hexEncode(encryptedData)));
		byte[] decryptedData = cryptoUtils.decryptData(encryptedData);
		Log.d(TAG, String.format("Decrypted data:%s", HexStringHelper.hexEncode(decryptedData)));
		assertEquals(INPUT_DATA, new String(decryptedData));
	}

	public void testDecryptData() {
		fail("Not yet implemented");
	}
	
}
