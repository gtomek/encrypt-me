package uk.org.tomek.encryptme.crypto;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Log;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import uk.org.tomek.encryptme.helpers.HexStringHelper;

/**
 * Creates encryption key used to encrypt/ decrypt the data.
 *
 * @author Tomasz Giszczak
 */
public final class KeyFactory {

    // logger TAG
    private static final String TAG = "KeyFactory";
    private static final String AES = "AES";
    private static final String KEY_PREFS = "key_prefs";
    private static final String ENCRYPTION_KEY = "encryption_key";
    private static final String STANDARD_KEY_ALG_KITCAT = "PBKDF2WithHmacSHA1And8bit";
    private static final String STANDARD_KEY_ALG_BEFORE_KITCAT = "PBKDF2WithHmacSHA1";
    private static final String BACKUP_KEY_ALG = "PBEWithMD5AndDES";
    private final SharedPreferences mSharedPreferences;
    private SecretKey mKey;

    // private constructor (please use newInstance() instead)
    private KeyFactory(final Context context) {
        if (context == null) {
            throw new IllegalArgumentException();
        }
        mSharedPreferences = context.getSharedPreferences(KEY_PREFS, Context.MODE_PRIVATE);
        // try to read saved key
        SecretKey savedKey = readSavedKey();
        if (savedKey == null) {
            // no saved key available, therefore create a new one
//            mKey = generateNewKeyNoPin();
        } else {
            mKey = savedKey;
            Log.d(TAG, String.format("Using saved key:%s", mKey.getEncoded()));
        }
    }

    /**
     * Creates new instance of {@link KeyFactory}.
     *
     * @return {@link KeyFactory}
     */
    public static KeyFactory newInstance(Context context) {
        return new KeyFactory(context);
    }

    /**
     * Returns default key created during class initialisation.
     *
     * @return default secret key
     */
    public SecretKey getKey() {
        return mKey;
    }

    /**
     * Generates secret key without PIN code.
     *
     * @return a key or null
     */
    public SecretKey generateKey() {
        // Generate a 128-bit key
        int outputKeyLength = 128;

        // check max supported key length for AES
        try {
            int maxAllowedKeyLength = Cipher.getMaxAllowedKeyLength(AES);
            Log.d(TAG, String.format("maxAllowedKeyLength for AES=%d", maxAllowedKeyLength));
            // set the output key length to 256 if supported
            if (maxAllowedKeyLength >= 256) {
                outputKeyLength = 256;
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        SecureRandom secureRandom = new SecureRandom();
        // Do *not* seed secureRandom! Automatically seeded from system entropy.
        KeyGenerator keyGenerator;
        SecretKey key = null;
        try {
            keyGenerator = KeyGenerator.getInstance(AES);
            keyGenerator.init(outputKeyLength, secureRandom);
            key = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            Log.d(TAG, "Impossible to create encryption key" + e.getClass().getSimpleName());
            e.printStackTrace();
        }
        return key;
    }

    /**
     * Generates secret code with PIN code used as an input parameter.
     *
     * @param passphraseOrPin initialisation password/PIN
     * @param salt initialisation salt
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public SecretKey generateKey(char[] passphraseOrPin, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Number of PBKDF2 hardening rounds to use. Larger values increase
        // computation time. You should select a value that causes computation
        // to take >100ms.
        final int iterations = 1000;

        // Generate a 128-bit key
        final int outputKeyLength = 128;

        // taking into account the change in KITKAT see
        // http://android-developers.blogspot.co.uk/2013/12/changes-to-secretkeyfactory-api-in.html
        SecretKeyFactory secretKeyFactory = null;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            // Use compatibility key factory -- only uses lower 8-bits of passphrase chars
            secretKeyFactory = SecretKeyFactory.getInstance(STANDARD_KEY_ALG_KITCAT);
        } else {
            // Traditional key factory. Will use lower 8-bits of passphrase chars on
            // older Android versions (API level 18 and lower) and all available bits
            // on KitKat and newer (API level 19 and higher).
            secretKeyFactory = SecretKeyFactory.getInstance(STANDARD_KEY_ALG_BEFORE_KITCAT);
        }
        KeySpec keySpec = new PBEKeySpec(passphraseOrPin, salt, iterations, outputKeyLength);
        return secretKeyFactory.generateSecret(keySpec);
    }

    /**
     * Store current key in persistent storage.
     */
    @TargetApi(Build.VERSION_CODES.GINGERBREAD)
    public void saveKey(final SecretKey key) {
        mKey = key;
        Editor preferencesEditor = mSharedPreferences.edit();
        byte[] encodedKeyBytes = key.getEncoded();
        Log.d(TAG,
                String.format("Saving binary key:%s", HexStringHelper.hexEncode(encodedKeyBytes)));
        preferencesEditor.putString(ENCRYPTION_KEY, new String(encodedKeyBytes,
                CryptoUtils.DEFAULT_CHARSET));
        preferencesEditor.commit();
    }

    /*
     * Reads and recreates previously saved key.
     */
    @TargetApi(Build.VERSION_CODES.GINGERBREAD)
    private SecretKey readSavedKey() {
        String keyString = mSharedPreferences.getString(ENCRYPTION_KEY, null);
        if (TextUtils.isEmpty(keyString)) {
            return null;
        } else {
            Log.d(TAG, String.format("Got String key:%s", keyString));
            SecretKeySpec secretKeySpec = new SecretKeySpec(
                    keyString.getBytes(CryptoUtils.DEFAULT_CHARSET), AES);
            Log.d(TAG,
                    String.format("Retrieved binary key:%s",
                            HexStringHelper.hexEncode(secretKeySpec.getEncoded()))
            );
            return secretKeySpec;
        }
    }

    /**
     * Creates new key without PIN, and stores it in a field.
     */
    public SecretKey generateNewKeyNoPin() {
        SecretKey keyNoPin = generateKey();
        Log.d(TAG, String.format("Created new key=%s",
                HexStringHelper.hexEncode(keyNoPin.getEncoded())));
        return keyNoPin;
    }

    /**
     * Generate key using package name and device ID as key generator inputs.
     *
     * @param context app context
     */
    public SecretKey generateKeyFromPackage(final Context context) {
        char[] packageChars = context.getPackageName().toCharArray();
        byte[] serialNumber = getDeviceSerial(context).getBytes();
        try {
            return generateKey(packageChars, serialNumber);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Returns device serial number as String.
     *
     * @return
     */
    private static String getDeviceSerial(Context context) {
        try {
            String deviceSerial = (String) Build.class.getField("SERIAL").get(null);

            // if it is still empty try a different way
            if (TextUtils.isEmpty(deviceSerial)) {
                deviceSerial = Settings.Secure.getString(context.getContentResolver(),
                        Settings.Secure.ANDROID_ID);
            }
            Log.d(TAG, String.format("Got serial number:%s", deviceSerial));

            return deviceSerial;
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
        return null;
    }
}
