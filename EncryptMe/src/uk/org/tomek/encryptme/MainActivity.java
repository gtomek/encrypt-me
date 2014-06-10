package uk.org.tomek.encryptme;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.TextView.OnEditorActionListener;

import javax.crypto.SecretKey;

import uk.org.tomek.encryptme.crypto.CryptoUtils;
import uk.org.tomek.encryptme.crypto.KeyFactory;
import uk.org.tomek.encryptme.helpers.HexStringHelper;
import uk.org.tomek.encryptme.presenters.MainActivityPresenter;
import uk.org.tomek.encryptme.views.MainScreenView;

/**
 * Main application activity.
 */
public final class MainActivity extends Activity implements MainScreenView {

    private static final String TAG = "MainActivity";
    private MainActivityPresenter mPresenter;
    private KeyFactory mKeyFactory;
    private TextView mEncryptionTypeTv;
    private TextView mKeyValueTv;
    private EditText mInputTextFiled;
    private TextView mOutputTextField;

    public MainActivity() {
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mKeyFactory = KeyFactory.newInstance(this);
        mPresenter = MainActivityPresenter.newInstance(CryptoUtils.newInstance(mKeyFactory));

        // create crypto utils instance
        final CryptoUtils cryptoUtils = CryptoUtils.newInstance(mKeyFactory);

        //get views
        mEncryptionTypeTv = (TextView) findViewById(R.id.encryption_type);
        mKeyValueTv = (TextView) findViewById(R.id.key_value);

        // set view in Presenter
        mPresenter.setView(this);

        // add action to input text field (pressing Enter should trigger encryption)
        mOutputTextField = (TextView) findViewById(R.id.output_text);
        mInputTextFiled = (EditText) findViewById(R.id.input_text);
        mInputTextFiled.setOnEditorActionListener(new OnEditorActionListener() {

            @Override
            public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                boolean isHandled = false;
                Log.d(TAG, String.format(
                        "setOnEditorActionListener triggered with actionId:%d, event_action:%s",
                        actionId, event));

                if (actionId == EditorInfo.IME_ACTION_DONE ||
                        actionId == EditorInfo.IME_NULL && event.getAction() == KeyEvent.KEYCODE_UNKNOWN) {
                    String inputText = mInputTextFiled.getText().toString();
                    Log.d(TAG, String.format("Input data:%s", inputText));

                    byte[] encryptedData = cryptoUtils.encryptData(inputText);
                    String hexEncodedOutput = HexStringHelper.hexEncode(encryptedData);
                    Log.d(TAG, String.format("Output data:%s", hexEncodedOutput));
                    mOutputTextField.setText(hexEncodedOutput);

                    // hide keyboard
                    InputMethodManager inputManager =
                            (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
                    inputManager.hideSoftInputFromWindow(getCurrentFocus().getWindowToken(),
                            InputMethodManager.HIDE_NOT_ALWAYS);

                    isHandled = true;
                }
                return isHandled;
            }
        });


        Button mCreateNewKeyButton = (Button) findViewById(R.id.create_new_key_button);
        mCreateNewKeyButton.setOnClickListener(new OnClickListener() {

            @Override
            public void onClick(View v) {
                SecretKey secretKey = mKeyFactory.generateKeyFromPackage(getApplicationContext());
                // save the key
                mKeyFactory.saveKey(secretKey);
                // refresh key values on the screen
                mPresenter.present();
            }
        });

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
        mEncryptionTypeTv.setText(type);
    }

    @Override
    public void showKeyContent(String key) {
        Log.d(TAG, "showKeyContent called");
        mKeyValueTv.setText(key);
    }


}
