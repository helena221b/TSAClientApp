package Gui;
import Code.Controller;
import Code.Controller.HashFunction;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.SystemColor;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.TimeZone;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JLayeredPane;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileSystemView;

import org.apache.pdfbox.pdmodel.encryption.SecurityProvider;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom.BigInteger;

import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JFileChooser;

public class Response extends JFrame {

	private Controller controller;
	private JPanel contentPane;
	private TimeStampResponse tsr;
	private TimeStampToken token;
	
	private String intToPKIStatusString(int i) {
		switch(i) {
		case 0:	return "granted";
		case 1: return "grantedWithMods";
		case 2: return "rejection";
		case 3: return "waiting";
		case 4: return "revocationWarning";
		case 5: return "revocationNotification";
		}
		return null;
	}
	
	private String toUTC(Date date) {
		final String ISO_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS zzz";
		final SimpleDateFormat sdf = new SimpleDateFormat();
		final TimeZone utc = TimeZone.getTimeZone("UTC");
		sdf.setTimeZone(utc);
		//System.out.println(sdf.format(date));
		return sdf.format(date);
	}

	/**
	 * Create the frame.
	 */
	public Response(Controller controller) {
		this.controller=controller;
		tsr=controller.getLastResponse();
		token=tsr.getTimeStampToken();
		//menu
		initMenu();
		
		//frame basic
		setTitle("Time Stamp Response");
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setBounds(100, 40, 911, 847);
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
		panel.setBounds(0, 0, 889, 767);
		contentPane.add(panel);
		panel.setLayout(null);
	
		
		//layeri
		JLayeredPane layeredPane = new JLayeredPane();
		layeredPane.setForeground(Color.WHITE);
		layeredPane.setBackground(SystemColor.inactiveCaption);
		layeredPane.setBounds(15, 16, 859, 120);
		layeredPane.setOpaque(true);
		panel.add(layeredPane);
		
		//status part
		initStatusPart(layeredPane);
		
		JLayeredPane layeredPane_1 = new JLayeredPane();
		layeredPane_1.setOpaque(true);
		layeredPane_1.setForeground(Color.WHITE);
		layeredPane_1.setBackground(SystemColor.inactiveCaption);
		layeredPane_1.setBounds(15, 152, 859, 141);
		panel.add(layeredPane_1);
		
		//TST Infos part
		initTSTInfoPart(layeredPane_1);
		
		JLayeredPane layeredPane_2 = new JLayeredPane();
		layeredPane_2.setOpaque(true);
		layeredPane_2.setForeground(Color.WHITE);
		layeredPane_2.setBackground(SystemColor.inactiveCaption);
		layeredPane_2.setBounds(15, 308, 859, 430);
		panel.add(layeredPane_2);
		
		//OtherPart
		initOtherPart(layeredPane_2);
		
		

	}
	
	private void initMenu() {
		
		JMenuBar menuBar=new JMenuBar();
		this.setJMenuBar(menuBar);
		JMenu certMenu= new JMenu("TSA Certificate");
		certMenu.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 20));
		menuBar.add(certMenu);
		//show cert
		JMenuItem showCert= new JMenuItem("Show TSA Certicate");
		showCert.setHorizontalAlignment(SwingConstants.LEFT);
		showCert.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 20));
		showCert.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				controller.makeCertFrame();
				
			}
		});
		//show chain certs
		JMenuItem showCertChain= new JMenuItem("Show Chain");
		showCertChain.setHorizontalAlignment(SwingConstants.CENTER);
		showCertChain.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 20));
		certMenu.add(showCert);
		certMenu.add(showCertChain);
		showCertChain.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				controller.makeChainFrame();
			}
		});
		
		JMenu timestampMenu =new JMenu("Timestamp");
		timestampMenu.setHorizontalAlignment(SwingConstants.LEFT);
		timestampMenu.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 20));
		menuBar.add(timestampMenu);
		//timestamp validity
		JMenuItem validateTimestamp= new JMenuItem("Validate Timestamp");
		validateTimestamp.setHorizontalAlignment(SwingConstants.CENTER);
		validateTimestamp.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 20));
		timestampMenu.add(validateTimestamp);
		validateTimestamp.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				 Collection<X509CertificateHolder> tstMatches = token.getCertificates().getMatches(token.getSID());
			     X509CertificateHolder holder = tstMatches.iterator().next();	//1. u chainu je TSA
				 X509Certificate tstCert=null;
					try {
						 tstCert = new JcaX509CertificateConverter().getCertificate(holder);
						 SignerInformationVerifier siv;	
						 siv = new JcaSimpleSignerInfoVerifierBuilder().setProvider(SecurityProvider.getProvider()).build(tstCert);
						 token.validate(siv);
						 System.out.println("TimeStampToken validated"); 
						 JOptionPane.showMessageDialog(null, "Time Stamp Token is valid.");
						 
					} catch (Exception ee) {
						// TODO Auto-generated catch block
						JOptionPane.showMessageDialog(null, "Time Stamp Token is not valid.");
						ee.printStackTrace();
					} 
				//TSPValidationException 
			}
		});
		
		
	}

	private void initStatusPart(JLayeredPane layeredPane) {
		JLabel status = new JLabel("Response Status:");
		status.setBackground(Color.CYAN);
		status.setBounds(15, 8, 212, 33);
		layeredPane.add(status);
		status.setForeground(SystemColor.controlDkShadow);
		status.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		
		JLabel statusString = new JLabel("Response Status String:");
		statusString.setForeground(SystemColor.controlDkShadow);
		statusString.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		statusString.setBackground(Color.CYAN);
		statusString.setBounds(15, 44, 271, 33);
		layeredPane.add(statusString);
		
		JLabel statusInfo = new JLabel("Response Failure Information:");
		statusInfo.setForeground(SystemColor.controlDkShadow);
		statusInfo.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		statusInfo.setBackground(Color.CYAN);
		statusInfo.setBounds(15, 80, 317, 33);
		layeredPane.add(statusInfo);
		
		//status
		JLabel outStatus = new JLabel();
		int st=tsr.getStatus();
		
		outStatus.setText(intToPKIStatusString(st));
		outStatus.setForeground(SystemColor.controlDkShadow);
		outStatus.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		outStatus.setBackground(Color.CYAN);
		outStatus.setBounds(430, 8, 212, 33);
		layeredPane.add(outStatus);
		//status string
		JLabel outStatusString = new JLabel();
		if(tsr.getStatusString()!=null)
			outStatusString.setText(tsr.getStatusString());
		else
			outStatusString.setText("N/A");
		outStatusString.setForeground(SystemColor.controlDkShadow);
		outStatusString.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		outStatusString.setBackground(Color.CYAN);
		outStatusString.setBounds(430, 44, 212, 33);
		layeredPane.add(outStatusString);
		//status failure info
		JLabel outStatusInfo = new JLabel();
		if(tsr.getFailInfo()!=null) 
			outStatusInfo.setText(tsr.getFailInfo().toString());
		else
			outStatusInfo.setText("N/A");
		outStatusInfo.setForeground(SystemColor.controlDkShadow);
		outStatusInfo.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		outStatusInfo.setBackground(Color.CYAN);
		outStatusInfo.setBounds(430, 80, 212, 33);
		layeredPane.add(outStatusInfo);
	}

	private void initTSTInfoPart(JLayeredPane layeredPane_1) {
		
		JLabel lblVersion = new JLabel("Version:");
		lblVersion.setForeground(SystemColor.controlDkShadow);
		lblVersion.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblVersion.setBackground(Color.CYAN);
		lblVersion.setBounds(15, 8, 212, 33);
		layeredPane_1.add(lblVersion);
		
		JLabel lblMessageImpringHash = new JLabel("Message Impring Hash Algorithm:");
		lblMessageImpringHash.setForeground(SystemColor.controlDkShadow);
		lblMessageImpringHash.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblMessageImpringHash.setBackground(Color.CYAN);
		lblMessageImpringHash.setBounds(15, 44, 349, 33);
		layeredPane_1.add(lblMessageImpringHash);
		
		JLabel lblMessageImpringHash_1 = new JLabel("Message Imprint Hash value:");
		lblMessageImpringHash_1.setForeground(SystemColor.controlDkShadow);
		lblMessageImpringHash_1.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblMessageImpringHash_1.setBackground(Color.CYAN);
		lblMessageImpringHash_1.setBounds(15, 80, 317, 33);
		layeredPane_1.add(lblMessageImpringHash_1);
		
		//version
		JLabel lblXx = new JLabel();
		lblXx.setText("v1");
		lblXx.setForeground(SystemColor.controlDkShadow);
		lblXx.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblXx.setBackground(Color.CYAN);
		lblXx.setBounds(403, 8, 212, 33);
		layeredPane_1.add(lblXx);
		
		//msg hash alg
		JLabel lblXx_1 = new JLabel();
		String hashAlg=token.getTimeStampInfo().getMessageImprintAlgOID().toString();
		lblXx_1.setText(HashFunction.oidToName(hashAlg));
		lblXx_1.setForeground(SystemColor.controlDkShadow);
		lblXx_1.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblXx_1.setBackground(Color.CYAN);
		lblXx_1.setBounds(403, 44, 430, 33);
		layeredPane_1.add(lblXx_1);
		
		//msg hash value
		JLabel lblXx_2 = new JLabel();
		lblXx_2.setText(new String(Hex.encode(token.getTimeStampInfo().getMessageImprintDigest())));
		lblXx_2.setForeground(SystemColor.controlDkShadow);
		lblXx_2.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblXx_2.setBackground(Color.CYAN);
		JScrollPane scrollHashValue =new JScrollPane(lblXx_2);
		scrollHashValue.setBounds(403, 80, 430, 55);
		layeredPane_1.add(scrollHashValue);
	}

	private void initOtherPart(JLayeredPane layeredPane_2) {
		
		//dohvati cert
		 Collection<X509CertificateHolder> tstMatches = token.getCertificates().getMatches(token.getSID());
	     X509CertificateHolder holder = tstMatches.iterator().next();	//1. u chainu je TSA
		 X509Certificate tstCert=null;
			try {
				  tstCert = new JcaX509CertificateConverter().getCertificate(holder);
				  
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 
		
		//polja na guiu
		JLabel lblTsaPolicyOid = new JLabel("TSA Policy OID:");
		lblTsaPolicyOid.setForeground(SystemColor.controlDkShadow);
		lblTsaPolicyOid.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblTsaPolicyOid.setBackground(Color.CYAN);
		lblTsaPolicyOid.setBounds(15, 8, 212, 33);
		layeredPane_2.add(lblTsaPolicyOid);
		
		JLabel lblTstSerialNumber = new JLabel("TST Serial Number:");
		lblTstSerialNumber.setForeground(SystemColor.controlDkShadow);
		lblTstSerialNumber.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblTstSerialNumber.setBackground(Color.CYAN);
		lblTstSerialNumber.setBounds(15, 44, 349, 33);
		layeredPane_2.add(lblTstSerialNumber);
		
		JLabel lblGenerationTime = new JLabel("Generation Time:");
		lblGenerationTime.setForeground(SystemColor.controlDkShadow);
		lblGenerationTime.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblGenerationTime.setBackground(Color.CYAN);
		lblGenerationTime.setBounds(15, 80, 317, 33);
		layeredPane_2.add(lblGenerationTime);
		
		//tsa policy oid
		JLabel label_3 = new JLabel();
		label_3.setText(token.getTimeStampInfo().getPolicy().toString());
		label_3.setForeground(SystemColor.controlDkShadow);
		label_3.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		label_3.setBackground(Color.CYAN);
		label_3.setBounds(403, 8, 441, 33);
		layeredPane_2.add(label_3);
		
		//tst serial num
		JLabel label_4 = new JLabel();
		label_4.setText(Integer.toString(token.getTimeStampInfo().getSerialNumber().intValue()));
		label_4.setForeground(SystemColor.controlDkShadow);
		label_4.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		label_4.setBackground(Color.CYAN);
		label_4.setBounds(403, 44, 212, 33);
		layeredPane_2.add(label_4);
		
		//BTN DOWNLOAD TS TOKEN
		JButton btnDownloadTst = new JButton("Download TST");
		btnDownloadTst.setForeground(Color.GRAY);
		btnDownloadTst.setFont(new Font("Yu Gothic Medium", Font.BOLD, 18));
		btnDownloadTst.setBackground(UIManager.getColor("Button.highlight"));
		btnDownloadTst.setBounds(591, 150, 191, 47);
		layeredPane_2.add(btnDownloadTst);
		btnDownloadTst.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				
				JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
				//jfc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				int returnValue = jfc.showSaveDialog(null);
				if (returnValue == JFileChooser.APPROVE_OPTION) {
					System.out.println("jfc name: "+jfc.getName());
					System.out.println("sel file name je: "+jfc.getSelectedFile().getName());
					System.out.println("sel file path je "+jfc.getSelectedFile().getPath());
					File file=new File(jfc.getSelectedFile().getPath());
					FileOutputStream fos;
					try {
						fos = new FileOutputStream(file);
						fos.write(controller.getTSTEncoded());
						fos.close();
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					
				}
				
			}
		});
		
		//general time
		JLabel label_5 = new JLabel();
		Date date=token.getTimeStampInfo().getGenTime();
		label_5.setText(date.toString());
		label_5.setForeground(SystemColor.controlDkShadow);
		label_5.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		label_5.setBackground(Color.CYAN);
		label_5.setBounds(403, 80, 430, 33);
		layeredPane_2.add(label_5);
		
		JLabel lblAccuracy = new JLabel("Accuracy Seconds:");
		lblAccuracy.setForeground(SystemColor.controlDkShadow);
		lblAccuracy.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblAccuracy.setBackground(Color.CYAN);
		lblAccuracy.setBounds(15, 116, 317, 33);
		layeredPane_2.add(lblAccuracy);
		
		JLabel lblAccuracyMillis = new JLabel("Accuracy Millis:");
		lblAccuracyMillis.setForeground(SystemColor.controlDkShadow);
		lblAccuracyMillis.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblAccuracyMillis.setBackground(Color.CYAN);
		lblAccuracyMillis.setBounds(15, 152, 317, 33);
		layeredPane_2.add(lblAccuracyMillis);
		
		JLabel lblAccuracyMicros = new JLabel("Accuracy micros:");
		lblAccuracyMicros.setForeground(SystemColor.controlDkShadow);
		lblAccuracyMicros.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblAccuracyMicros.setBackground(Color.CYAN);
		lblAccuracyMicros.setBounds(15, 188, 317, 33);
		layeredPane_2.add(lblAccuracyMicros);
		
		JLabel lblNonce = new JLabel("Nonce:");
		lblNonce.setForeground(SystemColor.controlDkShadow);
		lblNonce.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblNonce.setBackground(Color.CYAN);
		lblNonce.setBounds(15, 260, 317, 33);
		layeredPane_2.add(lblNonce);
		
		JLabel lblOrdering = new JLabel("Ordering:");
		lblOrdering.setForeground(SystemColor.controlDkShadow);
		lblOrdering.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblOrdering.setBackground(Color.CYAN);
		lblOrdering.setBounds(15, 224, 317, 33);
		layeredPane_2.add(lblOrdering);
		
		//seconds
		JLabel label = new JLabel();
		
		label.setText(Integer.toString(token.getTimeStampInfo().getGenTimeAccuracy().getSeconds()));
		label.setForeground(SystemColor.controlDkShadow);
		label.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		label.setBackground(Color.CYAN);
		label.setBounds(403, 116, 212, 33);
		layeredPane_2.add(label);
		
		//millis
		JLabel label_1 = new JLabel();
		label_1.setText(Integer.toString(token.getTimeStampInfo().getGenTimeAccuracy().getMillis()));
		label_1.setForeground(SystemColor.controlDkShadow);
		label_1.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		label_1.setBackground(Color.CYAN);
		label_1.setBounds(403, 152, 212, 33);
		layeredPane_2.add(label_1);
		
		//micros
		JLabel label_2 = new JLabel();
		label_2.setText(Integer.toString(token.getTimeStampInfo().getGenTimeAccuracy().getMicros()));
		label_2.setForeground(SystemColor.controlDkShadow);
		label_2.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		label_2.setBackground(Color.CYAN);
		label_2.setBounds(403, 188, 212, 33);
		layeredPane_2.add(label_2);
		
		//ordering
		JLabel label_6 = new JLabel();
		label_6.setText(Boolean.toString(token.getTimeStampInfo().isOrdered()));
		label_6.setForeground(SystemColor.controlDkShadow);
		label_6.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		label_6.setBackground(Color.CYAN);
		label_6.setBounds(403, 224, 212, 33);
		layeredPane_2.add(label_6);
		
		//nonce
		JLabel label_7 = new JLabel();
		label_7.setText(Hex.toHexString(token.getTimeStampInfo().getNonce().toByteArray()));
		label_7.setForeground(SystemColor.controlDkShadow);
		label_7.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		label_7.setBackground(Color.CYAN);
		label_7.setBounds(403, 260, 212, 33);
		layeredPane_2.add(label_7);
		
		JLabel lblTsaName = new JLabel("TSA Name:");
		lblTsaName.setForeground(SystemColor.controlDkShadow);
		lblTsaName.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblTsaName.setBackground(Color.CYAN);
		lblTsaName.setBounds(15, 296, 317, 33);
		layeredPane_2.add(lblTsaName);
		
		JLabel lblExtensions = new JLabel("Extensions:");
		lblExtensions.setForeground(SystemColor.controlDkShadow);
		lblExtensions.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblExtensions.setBackground(Color.CYAN);
		lblExtensions.setBounds(15, 352, 317, 33);
		layeredPane_2.add(lblExtensions);
		
		JLabel lblTstSignatureAlgorithm = new JLabel("TST Signature Algorithm:");
		lblTstSignatureAlgorithm.setForeground(SystemColor.controlDkShadow);
		lblTstSignatureAlgorithm.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblTstSignatureAlgorithm.setBackground(Color.CYAN);
		lblTstSignatureAlgorithm.setBounds(15, 388, 317, 33);
		layeredPane_2.add(lblTstSignatureAlgorithm);
		
		//TSA Name
		JLabel label_8 = new JLabel();
		label_8.setText(tstCert.getSubjectX500Principal().getName());
		label_8.setForeground(SystemColor.controlDkShadow);
		label_8.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		label_8.setBackground(Color.CYAN);
		JScrollPane scrollTSAName = new JScrollPane(label_8); 
		scrollTSAName.setBounds(403, 296, 441, 55);
		layeredPane_2.add(scrollTSAName);
		System.out.println("Ime TSA je "+tstCert.getSubjectX500Principal().getName());
		
		//Extensions
		JLabel label_9 = new JLabel();
		Extensions ext=token.getTimeStampInfo().getExtensions();
		label_9.setText(ext!=null?ext.toString():"N/A");
		label_9.setForeground(SystemColor.controlDkShadow);
		label_9.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		label_9.setBackground(Color.CYAN);
		label_9.setBounds(403, 352, 212, 33);
		layeredPane_2.add(label_9);
		
		//tst signature alg
		JLabel label_10 = new JLabel();
		String algName=tstCert.getSigAlgName(); 
		label_10.setText(algName);
		label_10.setForeground(SystemColor.controlDkShadow);
		label_10.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		label_10.setBackground(Color.CYAN);
		label_10.setBounds(403, 388, 212, 33);
		layeredPane_2.add(label_10);
		
		//validacija tokena
		SignerInformationVerifier siv;
		try {
			siv = new JcaSimpleSignerInfoVerifierBuilder().setProvider(SecurityProvider.getProvider()).build(tstCert);
			 token.validate(siv);
			 System.out.println("TimeStampToken validated");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
		/*System.out.println(" GET ACCURACY");
		System.out.println(token.getTimeStampInfo().getAccuracy().getSeconds()+" "+token.getTimeStampInfo().getAccuracy().getMillis()+" "+token.getTimeStampInfo().getAccuracy().getMicros());
		System.out.println(" GET GEN TIME ACCURACY");
		System.out.println(token.getTimeStampInfo().getGenTimeAccuracy().toString());*/
			
	}



}
