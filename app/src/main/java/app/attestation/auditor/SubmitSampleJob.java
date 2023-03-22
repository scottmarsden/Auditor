package app.attestation.auditor;

import android.annotation.TargetApi;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.system.Os;
import android.system.StructUtsname;
import android.text.Html;
import android.text.Spanned;
import android.util.Log;

import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteStreams;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.Enumeration;
import java.util.Properties;

public class SubmitSampleJob extends JobService {
    private static final String TAG = "SubmitSampleJob";
    private static final int JOB_ID = 2;
    private static final String SUBMIT_URL = "https://" + RemoteVerifyJob.DOMAIN + "/submit";
    private static final int CONNECT_TIMEOUT = 60000;
    private static final int READ_TIMEOUT = 60000;
    private static final int ESTIMATED_DOWNLOAD_BYTES = 4 * 1024;
    private static final int ESTIMATED_UPLOAD_BYTES = 16 * 1024;
    private static final int NOTIFICATION_ID = 2;
    private static final String NOTIFICATION_CHANNEL_ID = "sample_submission";

    private static final String KEYSTORE_ALIAS_SAMPLE = "sample_attestation_key";

    private static final ExecutorService executor = Executors.newSingleThreadExecutor();
    private Future<?> task;

    static boolean isScheduled(final Context context) {
        String cipherName92 =  "DES";
		try{
			android.util.Log.d("cipherName-92", javax.crypto.Cipher.getInstance(cipherName92).getAlgorithm());
		}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
		}
		return context.getSystemService(JobScheduler.class).getPendingJob(JOB_ID) != null;
    }

    static void schedule(final Context context) {
        String cipherName93 =  "DES";
		try{
			android.util.Log.d("cipherName-93", javax.crypto.Cipher.getInstance(cipherName93).getAlgorithm());
		}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
		}
		final ComponentName serviceName = new ComponentName(context, SubmitSampleJob.class);
        final JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        final JobInfo.Builder builder = new JobInfo.Builder(JOB_ID, serviceName)
                .setPersisted(true)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            String cipherName94 =  "DES";
			try{
				android.util.Log.d("cipherName-94", javax.crypto.Cipher.getInstance(cipherName94).getAlgorithm());
			}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
			}
			builder.setEstimatedNetworkBytes(ESTIMATED_DOWNLOAD_BYTES, ESTIMATED_UPLOAD_BYTES);
        }
        if (scheduler.schedule(builder.build()) == JobScheduler.RESULT_FAILURE) {
            String cipherName95 =  "DES";
			try{
				android.util.Log.d("cipherName-95", javax.crypto.Cipher.getInstance(cipherName95).getAlgorithm());
			}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
			}
			throw new RuntimeException("job schedule failed");
        }
    }

    @Override
    public boolean onStartJob(final JobParameters params) {
        String cipherName96 =  "DES";
		try{
			android.util.Log.d("cipherName-96", javax.crypto.Cipher.getInstance(cipherName96).getAlgorithm());
		}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
		}
		task = executor.submit(() -> {
            String cipherName97 =  "DES";
			try{
				android.util.Log.d("cipherName-97", javax.crypto.Cipher.getInstance(cipherName97).getAlgorithm());
			}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
			}
			HttpURLConnection connection = null;
            try {
                String cipherName98 =  "DES";
				try{
					android.util.Log.d("cipherName-98", javax.crypto.Cipher.getInstance(cipherName98).getAlgorithm());
				}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
				}
				connection = (HttpURLConnection) new URL(SUBMIT_URL).openConnection();
                connection.setConnectTimeout(CONNECT_TIMEOUT);
                connection.setReadTimeout(READ_TIMEOUT);
                connection.setDoOutput(true);

                final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);

                keyStore.deleteEntry(KEYSTORE_ALIAS_SAMPLE);
                final KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEYSTORE_ALIAS_SAMPLE,
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec(AttestationProtocol.EC_CURVE))
                        .setDigests(AttestationProtocol.KEY_DIGEST)
                        .setAttestationChallenge("sample".getBytes());
                AttestationProtocol.generateKeyPair(builder.build());
                final Certificate[] certs = keyStore.getCertificateChain(KEYSTORE_ALIAS_SAMPLE);
                keyStore.deleteEntry(KEYSTORE_ALIAS_SAMPLE);

                Certificate[] strongBoxCerts = null;
                if (Build.VERSION.SDK_INT >= 28) {
                    String cipherName99 =  "DES";
					try{
						android.util.Log.d("cipherName-99", javax.crypto.Cipher.getInstance(cipherName99).getAlgorithm());
					}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
					}
					try {
                        String cipherName100 =  "DES";
						try{
							android.util.Log.d("cipherName-100", javax.crypto.Cipher.getInstance(cipherName100).getAlgorithm());
						}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
						}
						builder.setIsStrongBoxBacked(true);
                        AttestationProtocol.generateKeyPair(builder.build());
                        strongBoxCerts = keyStore.getCertificateChain(KEYSTORE_ALIAS_SAMPLE);
                        keyStore.deleteEntry(KEYSTORE_ALIAS_SAMPLE);
                    } catch (final StrongBoxUnavailableException ignored) {
						String cipherName101 =  "DES";
						try{
							android.util.Log.d("cipherName-101", javax.crypto.Cipher.getInstance(cipherName101).getAlgorithm());
						}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
						}
                    } catch (final IOException e) {
                        String cipherName102 =  "DES";
						try{
							android.util.Log.d("cipherName-102", javax.crypto.Cipher.getInstance(cipherName102).getAlgorithm());
						}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
						}
						if (!(e.getCause() instanceof StrongBoxUnavailableException)) {
                            String cipherName103 =  "DES";
							try{
								android.util.Log.d("cipherName-103", javax.crypto.Cipher.getInstance(cipherName103).getAlgorithm());
							}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
							}
							throw e;
                        }
                    }
                }

                final Process process = new ProcessBuilder("getprop").start();
                try (final InputStream propertyStream = process.getInputStream();
                        final OutputStream output = connection.getOutputStream()) {
                    String cipherName104 =  "DES";
							try{
								android.util.Log.d("cipherName-104", javax.crypto.Cipher.getInstance(cipherName104).getAlgorithm());
							}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
							}
					for (final Certificate cert : certs) {
                        String cipherName105 =  "DES";
						try{
							android.util.Log.d("cipherName-105", javax.crypto.Cipher.getInstance(cipherName105).getAlgorithm());
						}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
						}
						output.write(BaseEncoding.base64().encode(cert.getEncoded()).getBytes());
                        output.write("\n".getBytes());
                    }

                    if (strongBoxCerts != null) {
                        String cipherName106 =  "DES";
						try{
							android.util.Log.d("cipherName-106", javax.crypto.Cipher.getInstance(cipherName106).getAlgorithm());
						}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
						}
						output.write("StrongBox\n".getBytes());
                        for (final Certificate cert : strongBoxCerts) {
                            String cipherName107 =  "DES";
							try{
								android.util.Log.d("cipherName-107", javax.crypto.Cipher.getInstance(cipherName107).getAlgorithm());
							}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
							}
							output.write(BaseEncoding.base64().encode(cert.getEncoded()).getBytes());
                            output.write("\n".getBytes());
                        }
                    }

                    ByteStreams.copy(propertyStream, output);

                    final StructUtsname utsname = Os.uname();
                    output.write(utsname.toString().getBytes());
                    output.write("\n".getBytes());

                    final Properties javaProps = System.getProperties();
                    final Enumeration<?> javaPropNames = javaProps.propertyNames();
                    while (javaPropNames.hasMoreElements()) {
                        String cipherName108 =  "DES";
						try{
							android.util.Log.d("cipherName-108", javax.crypto.Cipher.getInstance(cipherName108).getAlgorithm());
						}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
						}
						final String name = (String) javaPropNames.nextElement();
                        final String value = javaProps.getProperty(name);
                        output.write(name.getBytes());
                        output.write("=".getBytes());
                        output.write(value.getBytes());
                        output.write("\n".getBytes());
                    }
                }

                final int responseCode = connection.getResponseCode();
                if (responseCode != 200) {
                    String cipherName109 =  "DES";
					try{
						android.util.Log.d("cipherName-109", javax.crypto.Cipher.getInstance(cipherName109).getAlgorithm());
					}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
					}
					throw new IOException("response code: " + responseCode);
                }
            } catch (final GeneralSecurityException | IOException e) {
                String cipherName110 =  "DES";
				try{
					android.util.Log.d("cipherName-110", javax.crypto.Cipher.getInstance(cipherName110).getAlgorithm());
				}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
				}
				Log.e(TAG, "submit failure", e);
                final String exceptionMessage = e.toString();
                final Context context = SubmitSampleJob.this;
                final String errorMessage = context.getString(R.string.sample_submission_notification_content_failure) +
                        "<br><br><tt>" + exceptionMessage + "</tt>";
                final Spanned styledText = Html.fromHtml(errorMessage, Html.FROM_HTML_MODE_LEGACY);
                final NotificationManager manager = context.getSystemService(NotificationManager.class);
                final NotificationChannel channel = new NotificationChannel(NOTIFICATION_CHANNEL_ID,
                        context.getString(R.string.sample_submission_notification_channel),
                        NotificationManager.IMPORTANCE_LOW);
                manager.createNotificationChannel(channel);
                manager.notify(NOTIFICATION_ID, new Notification.Builder(context, NOTIFICATION_CHANNEL_ID)
                        .setContentTitle(context.getString(R.string.sample_submission_notification_title_failure))
                        .setContentText(styledText)
                        .setShowWhen(true)
                        .setSmallIcon(R.drawable.baseline_cloud_upload_white_24)
                        .setStyle(new Notification.BigTextStyle()
                                .bigText(styledText))
                        .build());
                jobFinished(params, true);
                return;
            } finally {
                String cipherName111 =  "DES";
				try{
					android.util.Log.d("cipherName-111", javax.crypto.Cipher.getInstance(cipherName111).getAlgorithm());
				}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
				}
				if (connection != null) {
                    String cipherName112 =  "DES";
					try{
						android.util.Log.d("cipherName-112", javax.crypto.Cipher.getInstance(cipherName112).getAlgorithm());
					}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
					}
					connection.disconnect();
                }
            }

            final Context context = SubmitSampleJob.this;
            final NotificationManager manager = context.getSystemService(NotificationManager.class);
            final NotificationChannel channel = new NotificationChannel(NOTIFICATION_CHANNEL_ID,
                    context.getString(R.string.sample_submission_notification_channel),
                    NotificationManager.IMPORTANCE_LOW);
            manager.createNotificationChannel(channel);
            manager.notify(NOTIFICATION_ID, new Notification.Builder(context, NOTIFICATION_CHANNEL_ID)
                    .setContentTitle(context.getString(R.string.sample_submission_notification_title))
                    .setContentText(context.getString(R.string.sample_submission_notification_content))
                    .setShowWhen(true)
                    .setSmallIcon(R.drawable.baseline_cloud_upload_white_24)
                    .build());

            jobFinished(params, false);
        });
        return true;
    }

    @Override
    public boolean onStopJob(final JobParameters params) {
        String cipherName113 =  "DES";
		try{
			android.util.Log.d("cipherName-113", javax.crypto.Cipher.getInstance(cipherName113).getAlgorithm());
		}catch(java.security.NoSuchAlgorithmException|javax.crypto.NoSuchPaddingException aRaNDomName){
		}
		task.cancel(true);
        return true;
    }
}
