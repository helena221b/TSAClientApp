package Gui;
import Code.*;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.SystemColor;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.StringTokenizer;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JLayeredPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import javax.swing.JTextField;

public class Certificate extends JFrame {

	private JPanel contentPane;
	private Controller controller;
	private TimeStampToken token;
	private X509Certificate cert;
	/**
	 * Launch the application.
	 */


	/**
	 * Create the frame.
	 */
	
	private String DERtoString(byte[] ext) {
		ASN1Primitive derObject ;
		String decoded="N/A";
		if(ext==null)
			return decoded;
		try {
			derObject  = JcaX509ExtensionUtils.parseExtensionValue(ext);
			
			decoded = derObject .toString();   
		} catch (IOException e) {
			e.printStackTrace();
		}
		return decoded;
	     
	}
	
	
	
	public String CRLDistributionPoints(X509Certificate cert) {
		try {
			byte[] extVal = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
			if (extVal == null)
				return "N/A";
			CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(extVal));
			DistributionPoint[] points = crlDistPoint.getDistributionPoints();
			System.out.println("DISTR POINTI");
			StringBuilder sb=new StringBuilder();
			
			
			for (DistributionPoint p : points) {
				//Distr Point Name
				sb.append("DistributionPointName: ");
				DistributionPointName dpn=p.getDistributionPoint();
				if(dpn!=null) {
					sb.append(dpn.getName().toString()+", ");
				}
				else {
					sb.append("N/A, ");
				}
				
				//Reasons
				sb.append("Reasons: ");
				ReasonFlags r=p.getReasons();
				if(r!=null) {
					sb.append(r.getString()+", ");
				}
				else {
					sb.append("N/A, ");
				}
				//CRLIssuer
				sb.append("CRLIssuer: ");
				GeneralNames tmp = p.getCRLIssuer();
				if (tmp != null) {
					GeneralName[] crlIssers = tmp.getNames();
					for (int i = 0; i < crlIssers.length; i++) {
						if (crlIssers[i].getTagNo() == GeneralName.uniformResourceIdentifier) {
							String issuerUrl = crlIssers[i].toString();
							sb.append(crlIssers[i].toString() +"  ");
						}
					}
				}
				else {
					sb.append("N/A  ");
				}
			}
			return sb.toString();
			
		}catch(Exception e) { return "N/A";}
		
	}
	 
	
	
	private String getExtendedKeyUsage(String oid) {
		switch(oid) {
		case "1.3.6.1.5.5.7.3.1":{ return "serverAuth"; }
		case "1.3.6.1.5.5.7.3.2":{ return "clientAuth"; }
		case "1.3.6.1.5.5.7.3.3":{ return "codeSigning"; }
		case "1.3.6.1.5.5.7.3.4":{ return "emailProtection"; }
		case "1.3.6.1.5.5.7.3.8":{ return "timeStamping"; }
		case "1.3.6.1.5.5.7.3.9":{ return "ocspSigning"; }
		}
		return "";
	}
	public Certificate(Controller controller) {
		this.controller=controller;
		token=controller.getLastResponse().getTimeStampToken();
		
		//get cert
		Store<X509CertificateHolder> store=token.getCertificates();
		Collection<X509CertificateHolder> matches=store.getMatches(token.getSID());
		Iterator<X509CertificateHolder> iter=matches.iterator();
		X509CertificateHolder holderCert = iter.next();
		try {
			cert = new JcaX509CertificateConverter().getCertificate(holderCert);
		}catch(Exception e) {}
		
		
		//Frame
		
		setTitle("TSA Certificate");
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setBounds(100, 40, 911, 943);
		contentPane = new JPanel();
		contentPane.setForeground(UIManager.getColor("Label.disabledShadow"));
		contentPane.setBackground(UIManager.getColor("CheckBox.highlight"));
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		JPanel panel = new JPanel();
		panel.setForeground(UIManager.getColor("InternalFrame.inactiveBorderColor"));
		panel.setBorder(null);
		panel.setBackground(SystemColor.text);
		panel.setBounds(0, 0, 889, 887);
		contentPane.add(panel);
		panel.setLayout(null);
	
		
		//layeri
		JLayeredPane layeredPane = new JLayeredPane();
		layeredPane.setForeground(Color.WHITE);
		layeredPane.setBackground(SystemColor.inactiveCaption);
		layeredPane.setBounds(15, 16, 859, 519);
		layeredPane.setOpaque(true);
		panel.add(layeredPane);
		
		
		JLayeredPane layeredPane_1 = new JLayeredPane();
		layeredPane_1.setOpaque(true);
		layeredPane_1.setForeground(Color.WHITE);
		layeredPane_1.setBackground(SystemColor.inactiveCaption);
		layeredPane_1.setBounds(15, 549, 859, 322);
		panel.add(layeredPane_1);
		
		initContent(layeredPane);
		initExtensions(layeredPane_1);
		
		
	}
	
	private void initContent(JLayeredPane layeredPane) {
		//labele
		JLabel version = new JLabel("Version:");
		version.setBackground(Color.CYAN);
		version.setBounds(27, 13, 212, 33);
		layeredPane.add(version);
		version.setForeground(SystemColor.controlDkShadow);
		version.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		
		JLabel sirNum = new JLabel("Serial number:");
		sirNum.setForeground(SystemColor.controlDkShadow);
		sirNum.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		sirNum.setBackground(Color.CYAN);
		sirNum.setBounds(27, 49, 271, 33);
		layeredPane.add(sirNum);
		
		JLabel idAlg = new JLabel("Signature algorithm:");
		idAlg.setForeground(SystemColor.controlDkShadow);
		idAlg.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		idAlg.setBackground(Color.CYAN);
		idAlg.setBounds(27, 85, 317, 33);
		layeredPane.add(idAlg);
		
		JLabel lblIssuer = new JLabel("Issuer:");
		lblIssuer.setForeground(SystemColor.controlDkShadow);
		lblIssuer.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblIssuer.setBackground(Color.CYAN);
		lblIssuer.setBounds(27, 130, 317, 33);
		layeredPane.add(lblIssuer);
		
		JLabel lblValidFrom = new JLabel("Valid from:");
		lblValidFrom.setForeground(SystemColor.controlDkShadow);
		lblValidFrom.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblValidFrom.setBackground(Color.CYAN);
		lblValidFrom.setBounds(27, 180, 317, 33);
		layeredPane.add(lblValidFrom);
		
		JLabel lblValidTo = new JLabel("Valid to:");
		lblValidTo.setForeground(SystemColor.controlDkShadow);
		lblValidTo.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblValidTo.setBackground(Color.CYAN);
		lblValidTo.setBounds(27, 216, 317, 33);
		layeredPane.add(lblValidTo);
		
		JLabel lblSubject = new JLabel("Subject:");
		lblSubject.setForeground(SystemColor.controlDkShadow);
		lblSubject.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblSubject.setBackground(Color.CYAN);
		lblSubject.setBounds(27, 265, 317, 33);
		layeredPane.add(lblSubject);
		
		JLabel lblPublicKey = new JLabel("Public key:");
		lblPublicKey.setForeground(SystemColor.controlDkShadow);
		lblPublicKey.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblPublicKey.setBackground(Color.CYAN);
		lblPublicKey.setBounds(27, 330, 317, 33);
		layeredPane.add(lblPublicKey);
		
		JLabel lblIssuerId = new JLabel("Issuer ID:");
		lblIssuerId.setForeground(SystemColor.controlDkShadow);
		lblIssuerId.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblIssuerId.setBackground(Color.CYAN);
		lblIssuerId.setBounds(27, 395, 317, 33);
		layeredPane.add(lblIssuerId);
		
		JLabel lblSubjectId = new JLabel("Subject ID:");
		lblSubjectId.setForeground(SystemColor.controlDkShadow);
		lblSubjectId.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblSubjectId.setBackground(Color.CYAN);
		lblSubjectId.setBounds(27, 466, 317, 33);
		layeredPane.add(lblSubjectId);
		
	
		
		///////////////////////////////////////////////////////////////////////
		
		//version
		JLabel outVersion = new JLabel();
		outVersion.setText("v"+Integer.toString(cert.getVersion()));
		outVersion.setForeground(SystemColor.controlDkShadow);
		outVersion.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		outVersion.setBackground(Color.CYAN);
		outVersion.setBounds(430, 13, 212, 33);
		layeredPane.add(outVersion);
		
		//sirial number
		JLabel outSirNum = new JLabel();
		outSirNum.setText(Integer.toString(cert.getSerialNumber().intValue()));
		outSirNum.setForeground(SystemColor.controlDkShadow);
		outSirNum.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		outSirNum.setBackground(Color.CYAN);
		outSirNum.setBounds(430, 49, 212, 33);
		layeredPane.add(outSirNum);
		
		//id algorithm
		JLabel alg = new JLabel();
		alg.setText(cert.getSigAlgName());
		alg.setForeground(SystemColor.controlDkShadow);
		alg.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		alg.setBackground(Color.CYAN);
		alg.setBounds(430, 85, 212, 33);
		layeredPane.add(alg);
		
		//issuer
		JLabel issuer = new JLabel();
		issuer.setText(cert.getIssuerX500Principal().getName());
		JScrollPane scrollIssuer=new JScrollPane(issuer);
		issuer.setForeground(SystemColor.controlDkShadow);
		issuer.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		scrollIssuer.setBackground(Color.CYAN);
		scrollIssuer.setBounds(430, 117, 412, 55);
		layeredPane.add(scrollIssuer);
		
		//validFrom
		JLabel validFrom = new JLabel();
		validFrom.setText(cert.getNotBefore().toString());
		validFrom.setForeground(SystemColor.controlDkShadow);
		validFrom.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		validFrom.setBackground(Color.CYAN);
		validFrom.setBounds(430, 180, 412, 33);
		layeredPane.add(validFrom);
		
		//validTo
		JLabel validTo = new JLabel();
		validTo.setText(cert.getNotAfter().toString());
		validTo.setForeground(SystemColor.controlDkShadow);
		validTo.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		validTo.setBackground(Color.CYAN);
		validTo.setBounds(430, 216, 414, 33);
		layeredPane.add(validTo);
		
		//subject
		JLabel subject = new JLabel();
		subject.setText(cert.getSubjectX500Principal().getName());
		JScrollPane scrollSubject=new JScrollPane(subject);
		subject.setForeground(SystemColor.controlDkShadow);
		subject.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		scrollSubject.setBackground(Color.CYAN);
		scrollSubject.setBounds(430, 248, 412, 55);
		layeredPane.add(scrollSubject);
		
		//public key
		JLabel pk = new JLabel();
		pk.setText(cert.getPublicKey().toString());
		JScrollPane scrollPK=new JScrollPane(pk);
		pk.setForeground(SystemColor.controlDkShadow);
		pk.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		scrollPK.setBackground(Color.CYAN);
		scrollPK.setBounds(430, 313, 412, 55);
		layeredPane.add(scrollPK);
		
		//issuer id
		JLabel issuerID = new JLabel();
		JScrollPane scrollIssuerID=new JScrollPane(issuerID);
		issuerID.setText(new String(Hex.encode(cert.getIssuerX500Principal().getEncoded())));
		issuerID.setForeground(SystemColor.controlDkShadow);
		issuerID.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		scrollIssuerID.setBackground(Color.CYAN);
		scrollIssuerID.setBounds(430, 378, 412, 55);
		layeredPane.add(scrollIssuerID);
		
		//subject id
		JLabel subjectID = new JLabel();
		JScrollPane scrollSubjectID=new JScrollPane(subjectID);
		subjectID.setText(new String(Hex.encode(cert.getSubjectX500Principal().getEncoded())));
		subjectID.setForeground(SystemColor.controlDkShadow);
		subjectID.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		scrollSubjectID.setBackground(Color.CYAN);
		scrollSubjectID.setBounds(430, 443, 412, 55);
		layeredPane.add(scrollSubjectID);	
	}
	
	public void initExtensions(JLayeredPane layeredPane_1){
		//labele
		
		JLabel lblExtensions = new JLabel("Basic constraints:");
		lblExtensions.setBounds(27, 13, 317, 33);
		layeredPane_1.add(lblExtensions);
		lblExtensions.setForeground(SystemColor.controlDkShadow);
		lblExtensions.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblExtensions.setBackground(Color.CYAN);
		
		JLabel lblSubjectKeyIdentifier = new JLabel("Subject key identifier:");
		lblSubjectKeyIdentifier.setForeground(SystemColor.controlDkShadow);
		lblSubjectKeyIdentifier.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblSubjectKeyIdentifier.setBackground(Color.CYAN);
		lblSubjectKeyIdentifier.setBounds(460, 13, 271, 33);
		layeredPane_1.add(lblSubjectKeyIdentifier);
		
		JLabel lblAuthorityKeyIdentifier = new JLabel("Authority key identifier:");
		lblAuthorityKeyIdentifier.setForeground(SystemColor.controlDkShadow);
		lblAuthorityKeyIdentifier.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblAuthorityKeyIdentifier.setBackground(Color.CYAN);
		lblAuthorityKeyIdentifier.setBounds(27, 116, 271, 33);
		layeredPane_1.add(lblAuthorityKeyIdentifier);
		
		JLabel lblKeyUsage = new JLabel("Key Usage:");
		lblKeyUsage.setForeground(SystemColor.controlDkShadow);
		lblKeyUsage.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblKeyUsage.setBackground(Color.CYAN);
		lblKeyUsage.setBounds(460, 116, 271, 33);
		layeredPane_1.add(lblKeyUsage);
		
		JLabel lblExtendedKeyUsage = new JLabel("Extended key usage");
		lblExtendedKeyUsage.setForeground(SystemColor.controlDkShadow);
		lblExtendedKeyUsage.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblExtendedKeyUsage.setBackground(Color.CYAN);
		lblExtendedKeyUsage.setBounds(27, 218, 317, 33);
		layeredPane_1.add(lblExtendedKeyUsage);
		
		JLabel lblPrivateKeyUsage = new JLabel("CRL distribution points:");
		lblPrivateKeyUsage.setForeground(SystemColor.controlDkShadow);
		lblPrivateKeyUsage.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblPrivateKeyUsage.setBackground(Color.CYAN);
		lblPrivateKeyUsage.setBounds(460, 218, 271, 33);
		layeredPane_1.add(lblPrivateKeyUsage);
		
		////////////////////////////////////////////////////////////
		
		//Basic constraints
		int len=cert.getBasicConstraints();
		String ca="No", path="None";
		if(len!=-1) {
			if(len==Integer.MAX_VALUE)
				path="No limit";
			else
				path=Integer.toString(len);
		}
		
		JLabel basicCon = new JLabel();
		basicCon.setText("CA: "+ca+", Path Length Constraint: "+path);
		basicCon.setForeground(SystemColor.controlDkShadow);
		basicCon.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		JScrollPane basicConstraints=new JScrollPane(basicCon);
		basicConstraints.setBounds(27, 45, 300, 55);
		layeredPane_1.add(basicConstraints);
		
		
		//Subject key identifier
		byte[] ski=cert.getExtensionValue("2.5.29.14");
		JLabel sKeyIdent = new JLabel();
		JScrollPane sKeyIdentScroll=new JScrollPane(sKeyIdent);
		if(ski!=null)
			sKeyIdent.setText(DERtoString(ski));
		else 
			sKeyIdent.setText("N/A");
		
		sKeyIdent.setForeground(SystemColor.controlDkShadow);
		sKeyIdent.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		sKeyIdentScroll.setBackground(Color.CYAN);
		sKeyIdentScroll.setBounds(460, 45, 300, 55);
		layeredPane_1.add(sKeyIdentScroll);
		
		//Authority key identifier
		byte[] aki=cert.getExtensionValue("2.5.29.35");
		JLabel authKeyIdent = new JLabel();
		JScrollPane authKeyIdentScroll=new JScrollPane(authKeyIdent);
		if(aki!=null)
			authKeyIdent.setText(DERtoString(aki));
		else 
			authKeyIdent.setText("N/A");
		authKeyIdent.setForeground(SystemColor.controlDkShadow);
		authKeyIdent.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		authKeyIdentScroll.setBackground(Color.CYAN);
		authKeyIdentScroll.setBounds(27, 150, 300, 55);
		layeredPane_1.add(authKeyIdentScroll);
		
		//key usage
		boolean[] usage=cert.getKeyUsage();
		StringBuilder sb=new StringBuilder();
		String[] keyUsageNames= {"digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"};
		for(int i=0;i<usage.length;i++) {
			if(usage[i])
				sb.append(keyUsageNames[i]+", ");
		}
		
		JLabel keyUsage = new JLabel();
		if(sb.toString().equals(""))
			keyUsage.setText("N/A");
		else
			keyUsage.setText(sb.toString().substring(0, sb.toString().length()-2));
		keyUsage.setForeground(SystemColor.controlDkShadow);
		keyUsage.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		JScrollPane keyUsageScroll=new JScrollPane(keyUsage);
		keyUsageScroll.setBounds(460, 150, 300, 55);
		layeredPane_1.add(keyUsageScroll);
		
		//extended key usage
		List<String> list=null;
		try {
			list=cert.getExtendedKeyUsage();
		} catch (CertificateParsingException e) {
			e.printStackTrace();
		}
		StringBuilder sb1=new StringBuilder();
		if(list!=null) 
			for(String s:list) 
				sb1.append(getExtendedKeyUsage(s)+", ");

		JLabel extKeyUsage = new JLabel();
		if(list==null)
			extKeyUsage.setText("N/A");
		else
			extKeyUsage.setText(sb1.toString().substring(0, sb1.toString().length()-2));
		extKeyUsage.setForeground(SystemColor.controlDkShadow);
		extKeyUsage.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		JScrollPane extKeyUsageScroll=new JScrollPane(extKeyUsage);
		extKeyUsageScroll.setBounds(27, 250, 300, 55);
		layeredPane_1.add(extKeyUsageScroll);
		
		
		//CRL distribution point
		byte[] pku=cert.getExtensionValue("2.5.29.16");
		JLabel cRLDistributionPoint = new JLabel();
		cRLDistributionPoint.setForeground(SystemColor.controlDkShadow);
		cRLDistributionPoint.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		JScrollPane cRlDistributionPointScroll=new JScrollPane(cRLDistributionPoint);
		cRlDistributionPointScroll.setBounds(460, 250, 300, 55);
		layeredPane_1.add(cRlDistributionPointScroll);
		cRLDistributionPoint.setText(CRLDistributionPoints(cert));
		

	}


	

}
