package Code;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;



import javax.inject.Inject;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.tsp.TimeStampReq;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;




public class TSAClient {

	@SuppressWarnings("unused")
	//private static final Logger logger = LoggerFactory.getLogger(TSAClient.class);
	
	
	private Controller controller;
	
	
	public TSAClient(Controller controller){
		this.controller=controller;
	}

	public byte[] signDetached(byte[] docBytes) throws IOException {
		System.out.println("usao u 1. signDetached");
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		signDetached(docBytes, os);
		byte[] t = os.toByteArray();
		os.close();
		return t;
	}

	private void signDetached(byte[] docBytes, ByteArrayOutputStream baos) throws IOException {
		System.out.println("usao u 2.. signDetached");
		PDDocument document = new PDDocument();
		document = PDDocument.load(docBytes);

		signDetached(document, baos);
		document.close();
	}

	private void signDetached(PDDocument document, OutputStream output) throws IOException {
		System.out.println("usao u 3. signDetached");
		
		int accessPermissions = PDUtils.getMDPPermission(document);
		if (accessPermissions == 1) {
			throw new IllegalStateException(
					"No changes to the document are permitted due to DocMDP transform parameters dictionary");
		}

		PDSignature signature = new PDSignature();
		signature.setType(COSName.DOC_TIME_STAMP);
		signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
		signature.setSubFilter(COSName.getPDFName("ETSI.RFC3161"));

		document.addSignature(signature, this.new Signatory());
		try {
		document.saveIncremental(output);
		}catch(Exception e) {
			return;
		}
	}
	
	protected URLConnection makeUrlConnection() throws IOException {
		URL url = new URL(controller.getTsaUrl());
		System.out.println("url iz TSAClient je "+url);
		
		URLConnection tsaConnection = url.openConnection();
		tsaConnection.setConnectTimeout(5000);
		tsaConnection.setDoInput(true);
		tsaConnection.setDoOutput(true);
		tsaConnection.setUseCaches(false);
		tsaConnection.setRequestProperty("Content-Type", "application/timestamp-query");
		tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");
		return tsaConnection;
	}

	protected byte[] getTSAResponse(byte[] requestBytes) throws IOException {
		
		URLConnection tsaConnection = makeUrlConnection();

		if (controller.getRegistration()) {
			String userPassword = controller.getUsername() + ":" + controller.getPassword();
			tsaConnection.setRequestProperty("Authorization",
					"Basic " + Base64.getEncoder().encodeToString(userPassword.getBytes()));
		}

		OutputStream out = tsaConnection.getOutputStream();
		out.write(requestBytes);
		out.close();

		byte[] respBytes = null;
		try (InputStream input = tsaConnection.getInputStream()) {
			respBytes = IOUtils.toByteArray(input);
		}
		catch(IOException e){
			controller.showMsg("TSA connection failed");
		}

		String encoding = tsaConnection.getContentEncoding();
		if (encoding != null && encoding.equalsIgnoreCase("base64")) {
			respBytes = Base64.getDecoder().decode(respBytes);
		}
		return respBytes;
	}

	
	//interface za potpisivanje
	private class Signatory implements SignatureInterface {

		protected TimeStampReq prepareRequest(InputStream content)throws IOException  {
			MessageDigest digest = null;
			try {
				digest = MessageDigest.getInstance(controller.getHashFunction().getCode());
			} catch (NoSuchAlgorithmException e) {

			}

			byte[] bytes = IOUtils.toByteArray(content);
			byte[] hash = digest.digest(bytes);

			DigestAlgorithmIdentifierFinder algorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
			AlgorithmIdentifier sha512oid = algorithmFinder.find(controller.getHashFunction().getName());
			ASN1ObjectIdentifier tsaPolicyId;
			String policy=controller.getPolicy();
			System.out.println("policy je "+policy);
			if(!policy.equals("none")) {
				ASN1ObjectIdentifier baseTsaPolicyId = new ASN1ObjectIdentifier(policy);
				tsaPolicyId= baseTsaPolicyId;
			}
			else
				tsaPolicyId= null;
			MessageImprint imp = new MessageImprint(sha512oid, hash);
			
			
			return new TimeStampReq(imp, tsaPolicyId, new ASN1Integer(controller.getRandom()),
					ASN1Boolean.TRUE, null);
		}
		
		@Override
		public byte[] sign(InputStream content) throws IOException {

			MessageDigest digest = null;
			
			
			TimeStampReq request = prepareRequest(content);
			byte[] body = request.getEncoded();
			//ceka response
			byte[] responseBytes = getTSAResponse(body);
			ASN1StreamParser asn1Sp = new ASN1StreamParser(responseBytes);
			TimeStampResp tspResp = TimeStampResp.getInstance(asn1Sp.readObject());
			
			TimeStampResponse tsr = null;
			try {
				tsr = new TimeStampResponse(tspResp);
				System.out.println("REsponse je ");
				System.out.println(tsr);
				System.out.println("Status je ");
				System.out.println(tsr.getStatusString());
			
			} catch (TSPException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			//checkForErrors(controller.getTsaUrl(), tsr);		//ako tsa nije dostupan
			// validate communication level attributes (RFC 3161 PKIStatus)
			try {
				tsr.validate(new TimeStampRequest(request));	//checks TS token if the status if GRANTED or GRANTED_WITH_MODS
			} catch (TSPException e) {							//compare nonce and hash??
				// TODO Auto-generated catch block
				e.printStackTrace();
				
			}
			if(tsr.getStatus()>1) {
				controller.showMsg(tsr.getStatusString());
				System.out.println(tsr.getFailInfo().toString());
				return null;
			}
			
			controller.setLastResponse(tsr);
			TimeStampToken token = tsr.getTimeStampToken();
			//token.getCertificates() vraca sertifikate dobijene od TSA kad je certReq==true
			//sa tim sertifikatima 
			return token.getEncoded();
		}

	}






}
