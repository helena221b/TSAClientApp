package Code;
import java.awt.EventQueue;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;

import javax.swing.JFrame;

import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import Gui.*;

public class Controller {
	private Home home; 
	private TSAClient tsaClient;
	private String username, password; 
	//defaultni params
	private String policy="1.3.6.1.4.1.99999.11.800.1.0";
	//private String tsaUrl="http://services.globaltrustfinder.com/adss/tsa";
	private String tsaUrl="http://test-tsa.ca.posta.rs/timestamp";
	private long random = new SecureRandom().nextLong();
	private String filePath="C:\\Users\\Jelena-PC\\Desktop\\", originalFileName="mjvm.pdf";
	private Boolean demandeCert=false;
	private Boolean registration=false;
	private TimeStampResponse lastResponse;
	

	private Boolean serverResponded=false;
	
	public enum HashFunction{
		SHA_1("1.3.14.3.2.26", "SHA-1"),
		SHA_224("2.16.840.1.101.3.4.2.4", "SHA-224"),
		SHA_256("2.16.840.1.101.3.4.2.1", "SHA-256"),
		SHA_384("2.16.840.1.101.3.4.2.2", "SHA-384"),
		SHA_512("2.16.840.1.101.3.4.2.3", "SHA-512");
				
		
		private String code;
		private String name;
		public String getCode() {
			return this.code;
		}
		public String getName() {
			return this.name;
		}
		public static String oidToName(String oid) {
			for(HashFunction m : HashFunction.values()) {
				if(m.code.equals(oid))
					return m.name;
			}
			return "";
		}
		private HashFunction(String code, String name) {
			this.code=code;
			this.name=name;
		}
	}
	
	private HashFunction hashFunction;
	
	public String getPolicy() {
		return policy;
	}

	public void setPolicy(String policy) {
		this.policy = policy;
	}

	public Controller() {
		this.tsaClient=new TSAClient(this);
		initGui();
	}
	
	public long getRandom() {
		return random;
	}

	public void setRandom(long random) {
		this.random = random;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getTsaUrl() {
		return tsaUrl;
	}

	public void setTsaUrl(String tsaUrl) {
		this.tsaUrl = tsaUrl;
	}

	
	private void initGui() {
		Controller controller=this;
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					home = new Home(controller);
					home.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
	
	public byte[] getTSTEncoded() {
		
		try {
			return lastResponse.getTimeStampToken().getEncoded();
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		return null;
	}
	
	private boolean isPDF(byte[] data) {
		if (data != null && data.length > 4 &&
	            data[0] == 0x25 && // %
	            data[1] == 0x50 && // P
	            data[2] == 0x44 && // D
	            data[3] == 0x46 && // F
	            data[4] == 0x2D) { // -
			//version
		//System.out.println(data[data.length - 7]+" "+data[data.length - 6]+" "+data[data.length - 5]+" "+ data[data.length - 4]+" "+data[data.length - 3]+" "+data[data.length - 2]+" "+data[data.length - 1]);
			//not testing format of ending the file because each version has different ending
			//and future versions would fail
			return true;
	        
	    }
	    return false;
	}

	public void showMsg(String msg) {
		home.showMsg(msg);
	}
	
	public void submit(String url, String username, String password, String nonceString, String policy, 
			String path, String fileName, Boolean certRequested, String hashStrnig, Boolean registration) throws Exception{

		this.originalFileName=fileName;
		this.filePath=path;
		this.random=Long.parseLong(nonceString);
		if(!policy.equals(""))
			this.policy=policy;
		else
			this.policy="none";
		this.username=username; this.password=password;
		this.tsaUrl=url;
		this.hashFunction=HashFunction.valueOf(hashStrnig);
		this.demandeCert=certRequested;
		this.registration=registration;
		
		this.serverResponded=false;
		this.lastResponse=null;
		System.out.println("url je "+this.tsaUrl);
		byte[] input_file = Files.readAllBytes(Paths.get(filePath));
		System.out.println(input_file);
		//only pdf docs are supported
		if(!isPDF(input_file)) {
			home.showMsg("Selected file is not a PDF document.");
			return;
		}
			
		byte[] encodedBytes = Base64.getEncoder().encode(input_file);
		String encodedString = new String(encodedBytes);
		//uzimam putanju plus ime original fajla bez pdf
		String newPath=filePath.substring(0, filePath.length()-4);
		FileOutputStream fos=null;
		try {
			fos= new FileOutputStream(newPath+"TS.pdf");
		}
		catch(Exception e) {
			showMsg("The process cannot access "+newPath+"TS.pdf" + " file because it is being used by another process");
			return;
		}
		
		System.out.println("ime out fajla je "+newPath+"TS.pdf");
		byte[] timestampedData = null;

		byte[] docBytes = Base64.getDecoder().decode(encodedString.getBytes());

		//Model call
		timestampedData = tsaClient.signDetached(docBytes);
		
		//doslo je do neke gerske i token nije vracen
		if(this.lastResponse==null) 
			return;
		
		OutputStream out = new FileOutputStream("out.pdf");
		out.write(timestampedData);
		out.close();
		fos.write(timestampedData);
		fos.flush();
		fos.close();
		
		this.serverResponded=true;

	}
	
	public void makeResponseFrame() {
		JFrame respFrame=new Response(this);
		//home.setEnabled(false);
		respFrame.setVisible(true);
	}
	
	public void makeChainFrame() {
		JFrame chainFrame=new Chain(this);
		chainFrame.setVisible(true);
	}
	
	public void makeCertFrame() {
		JFrame cert=new Certificate(this);
		cert.setVisible(true);
	}
	
	public String getFilePath() {
		return filePath;
	}

	public void setFilePath(String filePath) {
		this.filePath = filePath;
	}

	public String getOriginalFileName() {
		return originalFileName;
	}

	public void setOriginalFileName(String originalFileName) {
		this.originalFileName = originalFileName;
	}

	public Boolean getDemandeCert() {
		return demandeCert;
	}

	public void setDemandeCert(Boolean demandeCert) {
		this.demandeCert = demandeCert;
	}

	public Boolean getRegistration() {
		return registration;
	}

	public void setRegistration(Boolean registration) {
		this.registration = registration;
	}

	public HashFunction getHashFunction() {
		return hashFunction;
	}

	public void setHashFunction(HashFunction hashFunction) {
		this.hashFunction = hashFunction;
	}

	public static void main(String[] args) {
	
		Controller controller= new Controller();

	}
	
	public TimeStampResponse getLastResponse() {
		return lastResponse;
	}

	public void setLastResponse(TimeStampResponse lastResponse) {
		this.lastResponse = lastResponse;
	}

	public Boolean getServerResponded() {
		return serverResponded;
	}

	public void setServerResponded(Boolean serverResponded) {
		this.serverResponded = serverResponded;
	}

}
