package com.iiitd.qrc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.zip.GZIPInputStream;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.Toast;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

public class QRCActivity extends Activity {

	public static final String	server			= "http://moodle.iiitd.edu.in/providers/";
	public static final String	pubKeySuffix	= ".pub";
	private static final String	templateSuffix	= ".html";
	private String				provider;
	private byte[]				innerData;
	private byte[]				signature;
	private byte[]				providerPubKey;
	private byte[]				providerTemplate;

	@Override
	protected void onSaveInstanceState(Bundle outState) {
		super.onSaveInstanceState(outState);
		((WebView) findViewById(R.id.webMain)).saveState(outState);
		saveState(outState);
	}

	protected void restoreState(Bundle savedInstanceState) {
		Bundle qrcBundle = savedInstanceState.getBundle("com.iiitd.qrc");
		provider = qrcBundle.getString("provider");
		innerData = qrcBundle.getByteArray("innerData");
		signature = qrcBundle.getByteArray("signature");
		providerPubKey = qrcBundle.getByteArray("providerPubKey");
		providerTemplate = qrcBundle.getByteArray("providerTemplate");
	}

	protected void saveState(Bundle outState) {
		Bundle qrcBundle = new Bundle(5);
		qrcBundle.putString("provider", provider);
		qrcBundle.putByteArray("innerData", innerData);
		qrcBundle.putByteArray("signature", signature);
		qrcBundle.putByteArray("providerPubKey", providerPubKey);
		qrcBundle.putByteArray("providerTemplate", providerTemplate);
		outState.putBundle("com.iiitd.qrc", qrcBundle);
	}

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);

		Button button = (Button) findViewById(R.id.buttonCapture);
		button.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				callCapture();
			}
		});

		button = (Button) findViewById(R.id.buttonVerify);
		button.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				callVerify();
			}
		});

		if (savedInstanceState != null) {
			((WebView) findViewById(R.id.webMain))
					.restoreState(savedInstanceState);
			restoreState(savedInstanceState);
		}

	}

	public void callCapture() {
		innerData = null;
		signature = null;
		IntentIntegrator integrator = new IntentIntegrator(this);
		integrator.initiateScan();
		// parseQRData("com.iiitd.cse2008|H4sIAAAAAAAAAJ1U0WrbMBR931cIPYfNdrtu9Vvqlm2wLGMy9GGUcGOrtsCSwpW0EUL+fddxk5Ta7nDfbHF0dO49594ddz6U0nie7rgBLXnK54BesawGU/IZ36CtEDSd3+SyqOkEbdOsjOVpEkXXUZTMeBEQiWPlPPjgCHqvjJfIkihO6IKTWjr65+nv3eln9fTawhpnrWmxEWELG9DJA7L7XBW2bHGZuIuj+IQ4Xv9mPNoyFF4Rh7fsZydXK1O1WJSlotouZ5xODzw3fD8b4o773LeqUh4aliksgvJumDAbIUyGCB0ReMkW4GupwatihHRM5UWfVGypnZooDVTUW7JyTOYDWVFtgKdX7z8S5vjZvvTSlbOB8X9NSfp1ggcmPJItAaVjlCQ2byqLytd6YsVxnz6zehNaeUuswCgHrfkTzemz5rW0uGX2kXX8E1kX+dehfH5XRgK21cs1QteJ8g+YQpYsg6YITRjP1QTDRNBaYi5RvzStJ1Rkl5/75QvZPLIvaP/6+pme5KxHUNFPcqKjGP7jQ9eLV6b69QAtF8lA1zJKiipo9H5JKEdHeT5s7hDhqedv3Q/JwOQtNxIpJaZi3QxOWBB3IhuSmSMYR9uMsj2npAhVmXb/WEOclMZJoimQQ09QA9awVo3y20MaRRt0N76Jbp/F8NM5hFfX+4f9/t0/jrxmukAGAAA|MCwCFGwUHvSODphAlwt+Snl2JMLoQmxLAhRSri/FyErIco8ibwSHYRsPPfyS4A");
	}

	@Override
	public void onActivityResult(int requestCode, int resultCode, Intent intent) {
		IntentResult scanResult = IntentIntegrator.parseActivityResult(
				requestCode, resultCode, intent);
		if (scanResult != null)
			parseQRData(scanResult.getContents());
	}

	private byte[] readFromStream(InputStream stream) throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		byte[] b = new byte[1024];
		int bytesRead;
		while ((bytesRead = stream.read(b)) != -1)
			bos.write(b, 0, bytesRead);
		return bos.toByteArray();
	}

	public byte[] getFileContents(String filename) {
		byte[] fileContents = null;
		FileInputStream fis = null;

		try {
			fis = openFileInput(filename);
			fileContents = readFromStream(fis);
		} catch (IOException e) {
			logNotif("Error reading " + filename
					+ ". Attempting retrieval from " + server);
			try {
				fileContents = readFromStream((new URL(server + filename))
						.openStream());
				FileOutputStream fos = openFileOutput(filename,
						MODE_WORLD_READABLE);
				fos.write(fileContents);
			} catch (IOException e1) {
				logNotif("Error retreiving " + filename + " from server. "
						+ e1.getLocalizedMessage());
			}
		} finally {
			if (fis != null)
				try {
					fis.close();
				} catch (IOException e) {
				}
		}

		return fileContents;
	}

	private void logNotif(String msg) {
		Log.e("QRCActivity", msg);
		Toast.makeText(getApplicationContext(), msg, Toast.LENGTH_SHORT).show();
	}

	private void parseQRData(String contents) {
		String[] splutContents = contents.split("\\|");

		if ((provider == null) || !provider.equals(splutContents[0])) {
			provider = splutContents[0];
			providerPubKey = null;
			providerTemplate = null;
		}

		try {
			byte[] zInnerData = Base64.decode(splutContents[1], Base64.DEFAULT);
			GZIPInputStream zInnerDataStream = new GZIPInputStream(
					new ByteArrayInputStream(zInnerData));
			innerData = readFromStream(zInnerDataStream);
			zInnerDataStream.close();
		} catch (IOException e) {
			logNotif("Error reading innerData: " + e.getLocalizedMessage());
		}

		signature = Base64.decode(splutContents[2], Base64.DEFAULT);

		updateView("Unchecked", new String(innerData), getProviderTemplate());
	}

	public static Signature initPubDsa(byte[] pubKeyData)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			IOException, InvalidKeyException, NoSuchProviderException {
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyData);
		PublicKey pubKey = KeyFactory.getInstance("DSA", "BC").generatePublic(
				pubKeySpec);
		Signature dsa = Signature.getInstance("SHA1withDSA", "BC");
		dsa.initVerify(pubKey);
		return dsa;
	}

	public void callVerify() {
		try {
			boolean verified = verify(provider, innerData, signature);
			updateView(verified ? "true" : "false", new String(innerData),
					getProviderTemplate());
		} catch (Exception e) {
			logNotif("Exception while verifying: " + e.getLocalizedMessage());
		}
	}

	public String getProviderTemplate() {
		if (providerTemplate == null)
			providerTemplate = getFileContents(provider + templateSuffix);

		return new String(providerTemplate);
	}

	public byte[] getProviderKey() {
		if (providerPubKey == null)
			providerPubKey = getFileContents(provider + pubKeySuffix);

		return providerPubKey;
	}

	public void updateView(String verified, String innerData, String template) {
		WebView view = (WebView) findViewById(R.id.webMain);
		view.getSettings().setJavaScriptEnabled(true);
		String data = URLEncoder.encode(
				template.replace("$$VERIFIED$$", verified).replace(
						"$$INNERDATA$$", innerData)).replaceAll("\\+", " ");
		view.loadData(data, "text/html", "UTF8");
		// view.reload();
	}

	public boolean verify(String provider, byte[] innerData, byte[] signature)
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchProviderException, IOException,
			SignatureException {
		byte[] key = getFileContents(provider + pubKeySuffix);
		Signature dsa = initPubDsa(key);
		dsa.update(innerData);
		boolean verified = dsa.verify(signature);
		return verified;
	}
}
