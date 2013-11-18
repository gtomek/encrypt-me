package uk.org.tomek.encryptme;

import uk.org.tomek.encryptme.crypto.CryptoUtils;
import uk.org.tomek.encryptme.presenters.MainActivityPresenter;
import uk.org.tomek.encryptme.views.MainScreenView;
import android.app.Activity;
import android.os.Bundle;
import android.view.Menu;
import android.widget.TextView;

/**
 * Main application activity.
 */
public final class MainActivity extends Activity implements MainScreenView {
	
	private final MainActivityPresenter mPresenter;
	private TextView mEncryptionTypeTv;
	private TextView mKeyValueTv;
	
	public MainActivity() {
		this(MainActivityPresenter.newInstance(CryptoUtils.newInstance()));
	}

	public MainActivity(MainActivityPresenter mainActivityPresenter) {
		mPresenter = mainActivityPresenter;
	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		
		//get views 
		mEncryptionTypeTv = (TextView) findViewById(R.id.encryption_type);
		mKeyValueTv = (TextView) findViewById(R.id.key_value);
		
		// set view in Presenter
		mPresenter.setView(this);
		mPresenter.present();
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public void showEncryptionType(String type) {
		// TODO Auto-generated method stub
		mEncryptionTypeTv.setText(type);
	}

	@Override
	public void showKeyContent(String key) {
		mKeyValueTv.setText(key);
	}

}
