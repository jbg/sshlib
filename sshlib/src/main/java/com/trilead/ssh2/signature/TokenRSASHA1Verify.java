
package com.trilead.ssh2.signature;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;


import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;

import android.app.Activity;
import android.content.IntentSender;
import android.content.Intent;
import android.app.PendingIntent;



import org.openintents.openpgp.IOpenPgpService2;
import org.openintents.openpgp.OpenPgpDecryptionResult;
import org.openintents.openpgp.OpenPgpError;
import org.openintents.openpgp.OpenPgpSignatureResult;
import org.openintents.openpgp.util.OpenPgpApi;
import org.openintents.openpgp.util.OpenPgpServiceConnection;
import org.openintents.openpgp.util.OpenPgpUtils;


/**
 * TokenRSASHA1Verify.
 *
 * @author James McKenzie
 */
public class TokenRSASHA1Verify
{
  private static final Object lock = new Object();

  private static final Logger log = Logger.getLogger (TokenRSASHA1Verify.class);
  private static final int pending_intent_code = 28674;

  static private Activity activity;
  static private OpenPgpServiceConnection mServiceConnection;

  static private boolean async_semaphore = false;
  static private boolean async_abort = false;
  static private Intent  async_intent;

  public static void open (Activity _activity)
  {
    activity = _activity;

    if (activity == null)
      return;

    mServiceConnection = new OpenPgpServiceConnection (activity, "org.sufficientlysecure.keychain");
    mServiceConnection.bindToService();
  }


  public static void callback (int requestCode, int resultCode, Intent intent)
  {
    if (requestCode !=  pending_intent_code) return;

    synchronized (lock) {
      if (resultCode == Activity.RESULT_OK) {
        async_intent = intent;
        async_abort = false;
      } else
        async_abort = true;

      async_semaphore = true;

      lock.notify();
    }
  }

  public static byte[] generateSignature (byte[] message, TokenRSAPrivateKey pk) throws IOException
  {
    byte [] fail = new byte[0];
    long key_id = pk.getKeyId();

    if ((activity == null) || (mServiceConnection == null)) return fail;

    Intent data = new Intent();
    data.setAction (OpenPgpApi.ACTION_SSH_AUTH);
    data.putExtra (OpenPgpApi.EXTRA_SIGN_KEY_ID, key_id);

    InputStream is = new ByteArrayInputStream (message);

    OpenPgpApi api = new OpenPgpApi (activity, mServiceConnection.getService());
    Intent result = api.executeApi (data, is, null);


    int result_code;

    do {
      result_code = result.getIntExtra (OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR);

      if (result_code == OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED) {

        synchronized (lock) {
          async_semaphore = false;
          async_abort = true;

          PendingIntent pi = result.getParcelableExtra (OpenPgpApi.RESULT_INTENT);

          try {
            activity.startIntentSenderForResult (pi.getIntentSender(), pending_intent_code, null, 0, 0, 0);
          } catch (IntentSender.SendIntentException e) {
            return fail;
          }

          try {
            while (async_semaphore == false)
              lock.wait();
          } catch (InterruptedException e) { }

          if (async_abort)
            return fail;

          data = async_intent;
        }

        is = new ByteArrayInputStream (message);
        result = api.executeApi (data, is, null);

      } else
        break;

    } while (true);

    switch (result_code) {
    case OpenPgpApi.RESULT_CODE_SUCCESS: {

      byte [] output = result.getByteArrayExtra (OpenPgpApi.RESULT_DETACHED_SIGNATURE);

      if (output == null)
        return fail;

      return output;
    }

    case OpenPgpApi.RESULT_CODE_ERROR: {
      //OpenPgpError error = result.getParcelableExtra (OpenPgpApi.RESULT_ERROR);
      return fail;
    }
    }

    return fail;

  }

  public static void close()
  {
    if (mServiceConnection != null)
      mServiceConnection.unbindFromService();

    activity = null;
  }

}
