
package Code;
import java.io.IOException;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PDUtils {

	//private static final Logger LOG = LoggerFactory.getLogger(PDUtils.class);

	private PDUtils() {
	}

	public static int getMDPPermission(PDDocument doc) {
		COSBase base = doc.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.PERMS);
		if (base instanceof COSDictionary) {
			COSDictionary permsDict = (COSDictionary) base;
			base = permsDict.getDictionaryObject(COSName.DOCMDP);
			if (base instanceof COSDictionary) {
				COSDictionary signatureDict = (COSDictionary) base;
				base = signatureDict.getDictionaryObject("Reference");
				if (base instanceof COSArray) {
					COSArray refArray = (COSArray) base;
					for (int i = 0; i < refArray.size(); ++i) {
						base = refArray.getObject(i);
						if (base instanceof COSDictionary) {
							COSDictionary sigRefDict = (COSDictionary) base;
							if (COSName.DOCMDP.equals(sigRefDict.getDictionaryObject("TransformMethod"))) {
								base = sigRefDict.getDictionaryObject("TransformParams");
								if (base instanceof COSDictionary) {
									COSDictionary transformDict = (COSDictionary) base;
									int accessPermissions = transformDict.getInt(COSName.P, 2);
									if (accessPermissions < 1 || accessPermissions > 3) {
										accessPermissions = 2;
									}
									return accessPermissions;
								}
							}
						}
					}
				}
			}
		}
		return 0;
	}

	static public void setMDPPermission(PDDocument doc, PDSignature signature, int accessPermissions) {
		COSDictionary sigDict = signature.getCOSObject();

		// DocMDP specific stuff
		COSDictionary transformParameters = new COSDictionary();
		transformParameters.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"));
		transformParameters.setInt(COSName.P, accessPermissions);
		transformParameters.setName(COSName.V, "1.2");
		transformParameters.setNeedToBeUpdated(true);

		COSDictionary referenceDict = new COSDictionary();
		referenceDict.setItem(COSName.TYPE, COSName.getPDFName("SigRef"));
		referenceDict.setItem("TransformMethod", COSName.DOCMDP);
		referenceDict.setItem("DigestMethod", COSName.getPDFName("SHA1"));
		referenceDict.setItem("TransformParams", transformParameters);
		referenceDict.setNeedToBeUpdated(true);

		COSArray referenceArray = new COSArray();
		referenceArray.add(referenceDict);
		sigDict.setItem("Reference", referenceArray);
		referenceArray.setNeedToBeUpdated(true);

		// Catalog
		COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
		COSDictionary permsDict = new COSDictionary();
		catalogDict.setItem(COSName.PERMS, permsDict);
		permsDict.setItem(COSName.DOCMDP, signature);
		catalogDict.setNeedToBeUpdated(true);
		permsDict.setNeedToBeUpdated(true);
	}

	public static void checkCertificateUsage(X509Certificate x509Certificate) throws CertificateParsingException {
		// Check whether signer certificate is "valid for usage"
		// https://stackoverflow.com/a/52765021/535646
		// https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSig/changes.html#id1
		boolean[] keyUsage = x509Certificate.getKeyUsage();
		if (keyUsage != null && !keyUsage[0] && !keyUsage[1]) {
			// (unclear what "signTransaction" is)
			// https://tools.ietf.org/html/rfc5280#section-4.2.1.3
			//LOG.error("Certificate key usage does not include " + "digitalSignature nor nonRepudiation");
		}
		List<String> extendedKeyUsage = x509Certificate.getExtendedKeyUsage();
		if (extendedKeyUsage != null && !extendedKeyUsage.contains(KeyPurposeId.id_kp_emailProtection.toString())
				&& !extendedKeyUsage.contains(KeyPurposeId.id_kp_codeSigning.toString())
				&& !extendedKeyUsage.contains(KeyPurposeId.anyExtendedKeyUsage.toString())
				&& !extendedKeyUsage.contains("1.2.840.113583.1.1.5") &&
				// not mentioned in Adobe document, but tolerated in practice
				!extendedKeyUsage.contains("1.3.6.1.4.1.311.10.3.12")) {
			/*LOG.error("Certificate extended key usage does not include "
					+ "emailProtection, nor codeSigning, nor anyExtendedKeyUsage, "
					+ "nor 'Adobe Authentic Documents Trust'");*/
		}
	}

	public static void checkTimeStampCertificateUsage(X509Certificate x509Certificate)
			throws CertificateParsingException {
		List<String> extendedKeyUsage = x509Certificate.getExtendedKeyUsage();
		// https://tools.ietf.org/html/rfc5280#section-4.2.1.12
		if (extendedKeyUsage != null && !extendedKeyUsage.contains(KeyPurposeId.id_kp_timeStamping.toString())) {
			//LOG.error("Certificate extended key usage does not include timeStamping");
		}
	}

	public static void checkResponderCertificateUsage(X509Certificate x509Certificate)
			throws CertificateParsingException {
		List<String> extendedKeyUsage = x509Certificate.getExtendedKeyUsage();
		// https://tools.ietf.org/html/rfc5280#section-4.2.1.12
		if (extendedKeyUsage != null && !extendedKeyUsage.contains(KeyPurposeId.id_kp_OCSPSigning.toString())) {
			//LOG.error("Certificate extended key usage does not include OCSP responding");
		}
	}

	public static PDSignature getLastRelevantSignature(PDDocument document) throws IOException {
		SortedMap<Integer, PDSignature> sortedMap = new TreeMap<>();
		for (PDSignature signature : document.getSignatureDictionaries()) {
			int sigOffset = signature.getByteRange()[1];
			sortedMap.put(sigOffset, signature);
		}
		if (sortedMap.size() > 0) {
			PDSignature lastSignature = sortedMap.get(sortedMap.lastKey());
			COSBase type = lastSignature.getCOSObject().getItem(COSName.TYPE);
			if (type.equals(COSName.SIG) || type.equals(COSName.DOC_TIME_STAMP)) {
				return lastSignature;
			}
		}
		return null;
	}
}
