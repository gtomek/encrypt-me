package uk.org.tomek.encryptme.views;

public interface MainScreenView {
	
	/**
	 * Sets the encryption type on the main screen.
	 * 
	 * @param type
	 */
	void showEncryptionType(String type); 

	/**
	 * Sets the key value on the main screen.
	 * 
	 * @param key
	 */
	void showKeyContent(String key);
}
