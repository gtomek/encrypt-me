package uk.org.tomek.encryptme;

import uk.org.tomek.encryptme.crypto.CryptoUtils;
import uk.org.tomek.encryptme.crypto.KeyFactory;
import uk.org.tomek.encryptme.helpers.HexStringHelper;
import uk.org.tomek.encryptme.presenters.MainActivityPresenter;
import uk.org.tomek.encryptme.views.MainScreenView;
import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.inputmethod.EditorInfo;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.TextView.OnEditorActionListener;

/**
 * Main application activity.
 */
public final class MainActivity extends Activity implements MainScreenView{
	
	private static final String TAG = "MainActivity";
	private final MainActivityPresenter mPresenter;
	private final KeyFactory mKeyFactory;
	private TextView mEncryptionTypeTv;
	private TextView mKeyValueTv;
	private EditText mInputTextFiled;
	private TextView mOutputTextField;
	
	public MainActivity() {
		mKeyFactory = KeyFactory.newInstance();
		mPresenter = MainActivityPresenter.newInstance(CryptoUtils.newInstance(mKeyFactory));
//		this(MainActivityPresenter.newInstance(CryptoUtils.newInstance(mKeyFactory)));
	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		
		// create crypto utils instance
		final CryptoUtils cryptoUtils = CryptoUtils.newInstance(mKeyFactory);
		
		//get views 
		mEncryptionTypeTv = (TextView) findViewById(R.id.encryption_type);
		mKeyValueTv = (TextView) findViewById(R.id.key_value);
		
		// set view in Presenter
		mPresenter.setView(this);
		mPresenter.present();
		
		// add action to input text field (pressing Enter should trigger encryption)
		mOutputTextField = (TextView) findViewById(R.id.output_text);
		mInputTextFiled = (EditText) findViewById(R.id.input_text);
		mInputTextFiled.setOnEditorActionListener(new OnEditorActionListener() {
			
			@Override
			public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
				boolean handeled = false;
				
				if (actionId == EditorInfo.IME_NULL && event.getAction() == KeyEvent.KEYCODE_UNKNOWN) {
					String inputText = mInputTextFiled.getText().toString();
					Log.d(TAG, String.format("Input data:%s", inputText));
					
					byte[] encryptedData = cryptoUtils.encryptData(inputText);
					String hexEncodedOutput = HexStringHelper.hexEncode(encryptedData);
					Log.d(TAG, String.format("Output data:%s", hexEncodedOutput));
					mOutputTextField.setText(hexEncodedOutput);
					handeled = true;
				}
				return handeled;
			}
		});
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
