package uk.org.tomek.encryptme.presenters;

import uk.org.tomek.encryptme.crypto.CryptoUtils;
import uk.org.tomek.encryptme.helpers.HexStringHelper;
import uk.org.tomek.encryptme.views.MainScreenView;

/**
 * Presenter for the main activity. 
 */
public final class MainActivityPresenter {
	
	private final CryptoUtils mCryptoUtils;
	private MainScreenView mMainViewView;

	private MainActivityPresenter(CryptoUtils cryptoUtils) {
		mCryptoUtils = cryptoUtils;
	}

	public static MainActivityPresenter newInstance(CryptoUtils cryptoUtils) {
		return new MainActivityPresenter(cryptoUtils);
	}

	/**
	 * Sets the View in the presenter.
	 * 
	 * @param mainView
	 */
	public void setView(MainScreenView mainView) {
		mMainViewView = mainView;
	}

	/**
	 * Displays the data in the view.
	 */
	public void present() {
        if (mCryptoUtils.getKey() != null) {
            mMainViewView.showKeyContent(HexStringHelper.hexEncode(mCryptoUtils.getKey().getEncoded()));
        }
		mMainViewView.showEncryptionType(mCryptoUtils.getCipherAlgo());
	}

}
