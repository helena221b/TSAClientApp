package Gui;

import Code.*;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.SystemColor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JLayeredPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

public class Chain extends JFrame {

	private JPanel contentPane;
	private Controller controller;
	private TimeStampToken token;
	private TimeStampResponse tsr;

	/**
	 * Launch the application.
	 */

	/**
	 * Create the frame.
	 */
	public Chain(Controller controller) {

		this.controller = controller;
		tsr = controller.getLastResponse();
		token = tsr.getTimeStampToken();
		// frame
		setTitle("Chain of certificates");
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setBounds(100, 100, 1034, 358);
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
		panel.setBounds(0, 0, 1012, 302);
		contentPane.add(panel);
		panel.setLayout(null);

		JLayeredPane layeredPane = new JLayeredPane();
		layeredPane.setForeground(Color.WHITE);
		layeredPane.setBackground(SystemColor.inactiveCaption);
		layeredPane.setBounds(15, 16, 982, 273);
		layeredPane.setOpaque(true);
		panel.add(layeredPane);
		initContent(layeredPane);
	}

	private void initContent(JLayeredPane layeredPane) {
		Store<X509CertificateHolder> store = token.getCertificates();
		Collection<X509CertificateHolder> matches = store.getMatches(null);
		Iterator<X509CertificateHolder> iter = matches.iterator();
		X509Certificate cert = null;
		X509Certificate[] chain = new X509Certificate[matches.size()];
		System.out.println("CHAIN:");
		int x = 0, y = 0, index = 0;
		while (iter.hasNext()) {
			X509CertificateHolder holderCert = iter.next();
			try {
				chain[index++] = new JcaX509CertificateConverter().getCertificate(holderCert);
				// new label

			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		// prvi u nizu TSA cert
		JLabel label = new JLabel();
		JScrollPane scroll = new JScrollPane(label);
		label.setText(chain[0].getSubjectX500Principal().getName());
		label.setBackground(Color.CYAN);
		if (x + 15 < 620)
			scroll.setBounds(15 + x, 10 + y, 950 - x, 55);
		else
			scroll.setBounds(650, 10 + y, 315, 55);
		layeredPane.add(scroll);

		label.setForeground(SystemColor.controlDkShadow);
		label.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		x += 20;
		y += 65;
		
		
		// ostatak chaina u nazad
		for (int i = chain.length - 1; i > 0; i--) {
			JLabel label2 = new JLabel();
			JScrollPane scroll2 = new JScrollPane(label2);
			label2.setText(chain[i].getSubjectX500Principal().getName());
			label2.setBackground(Color.CYAN);
			if (x + 15 < 620)
				scroll2.setBounds(15 + x, 10 + y, 950 - x, 55);
			else
				scroll2.setBounds(650, 10 + y, 315, 55);
			layeredPane.add(scroll2);

			label2.setForeground(SystemColor.controlDkShadow);
			label2.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
			x += 20;
			y += 65;
			
		}
	}

}
