package Gui;
import Code.Controller;
import Code.TSAClient;

import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileSystemView;

import org.bouncycastle.util.Longs;
import org.bouncycastle.util.encoders.Hex;

import java.awt.SystemColor;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;

import javax.swing.UIManager;
import java.awt.FlowLayout;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import java.awt.Font;
import java.awt.Image;

import javax.swing.JSeparator;
import javax.swing.JLayeredPane;
import java.awt.Color;
import java.awt.Component;

import javax.swing.JTextField;
import javax.swing.ListCellRenderer;
import javax.swing.SwingConstants;
import javax.swing.JRadioButton;
import javax.swing.JList;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.border.BevelBorder;
import javax.swing.ListSelectionModel;
import javax.swing.AbstractListModel;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JTextArea;
import javax.swing.JButton;

public class Home extends JFrame {

	private Controller controller;
	private JPanel contentPane;
	private JTextField textUsername;
	private JTextField textPassword;
	private JTextField textNonce;
	private JTextField textPolicyOid;
	private JTextField textFilePath;
	private File selectedFile;

	/**
	 * Launch the application.
	 */
	/*public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Home frame = new Home(new Controller(new TSAClient()));
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}*/
	
	//renderer class for the list of algorithms
	 class MyComboBoxRenderer extends JLabel implements ListCellRenderer
	    {

	        public MyComboBoxRenderer() {}
	        @Override
	        public Component getListCellRendererComponent(JList list, Object value,
	                int index, boolean isSelected, boolean hasFocus)
	        {
	            setText(value.toString());
	            return this;
	        }
	    }

	public void showMsg(String msg) {
		JOptionPane.showMessageDialog(null, msg);
	}
	 
	public Home(Controller controller) {
		this.controller=controller;
		
		//menu
		JMenuBar menuBar=new JMenuBar();
		this.setJMenuBar(menuBar);
		JMenu responseMenu= new JMenu("TSA Response");
		responseMenu.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 20));
		menuBar.add(responseMenu);
		JMenuItem showResponse= new JMenuItem("Show TSA Rsponse");
		showResponse.setHorizontalAlignment(SwingConstants.CENTER);
		showResponse.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 20));
		JFrame myFrame=this;
		
		//response tab
		showResponse.addActionListener(new ActionListener() {	
			@Override
			public void actionPerformed(ActionEvent e) {
				if(!controller.getServerResponded()) {
					JOptionPane.showMessageDialog(null, "There is no response.");
					return;
				}
				else {
					controller.makeResponseFrame();
				}	
			}
		});
		
		JMenuItem showTSToken= new JMenuItem("Show Time Stamp Token");
		showTSToken.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 20));
		showTSToken.setHorizontalAlignment(SwingConstants.CENTER);
		
		responseMenu.add(showResponse);
		//tokenMenu.add(showTSToken);
		
		
		//frame
		setTitle("TSA Client Application");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 40, 911, 814);
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
		panel.setBounds(0, 0, 889, 723);
		contentPane.add(panel);
		panel.setLayout(null);
	
		
		//layeri
		JLayeredPane layeredPane = new JLayeredPane();
		layeredPane.setForeground(Color.WHITE);
		layeredPane.setBackground(SystemColor.inactiveCaption);
		layeredPane.setBounds(15, 16, 859, 98);
		layeredPane.setOpaque(true);
		panel.add(layeredPane);
		
		//url
		JLabel lblNewLabel = new JLabel("TSA server address:");
		lblNewLabel.setBackground(Color.CYAN);
		lblNewLabel.setBounds(120, 26, 212, 46);
		layeredPane.add(lblNewLabel);
		lblNewLabel.setForeground(SystemColor.controlDkShadow);
		lblNewLabel.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		
		//combo box za URL
		JComboBox<String> comboBoxUrl = new JComboBox<String>();
		comboBoxUrl.setBackground(Color.WHITE);
		comboBoxUrl.setEditable(true);
		comboBoxUrl.setModel(new DefaultComboBoxModel(new String[] {"http://test-tsa.ca.posta.rs/timestamp", "http://test-tsa.ca.posta.rs/timestamp1", "http://tsp.iaik.tugraz.at/tsp/TspRequest"}));
		comboBoxUrl.setSelectedIndex(0);
		comboBoxUrl.setOpaque(true);
		comboBoxUrl.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 18));
		comboBoxUrl.setBounds(449, 26, 373, 46);
		layeredPane.add(comboBoxUrl);
		
		//slicica-stit
		JLabel lblNewLabel_1 = new JLabel("");
		lblNewLabel_1.setBounds(41, 9, 64, 84);
		layeredPane.add(lblNewLabel_1);
		Image img=new ImageIcon(this.getClass().getResource("/stit.png")).getImage();
		lblNewLabel_1.setIcon(new ImageIcon(img));
		
		
		JLayeredPane layeredPane_1 = new JLayeredPane();
		layeredPane_1.setOpaque(true);
		layeredPane_1.setForeground(Color.WHITE);
		layeredPane_1.setBackground(SystemColor.inactiveCaption);
		layeredPane_1.setBounds(15, 130, 859, 168);
		panel.add(layeredPane_1);
		
		//username
		JLabel lblUsername = new JLabel("Username:");
		lblUsername.setForeground(new Color(105, 105, 105));
		lblUsername.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblUsername.setBounds(329, 30, 191, 46);
		layeredPane_1.add(lblUsername);
		
		textUsername = new JTextField();
		textUsername.setEnabled(false);
		textUsername.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 16));
		textUsername.setHorizontalAlignment(SwingConstants.CENTER);
		textUsername.setColumns(10);
		textUsername.setBackground(Color.WHITE);
		textUsername.setBounds(498, 29, 322, 51);
		layeredPane_1.add(textUsername);
		
		//password
		textPassword = new JTextField();
		textPassword.setEnabled(false);
		textPassword.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 16));
		textPassword.setHorizontalAlignment(SwingConstants.CENTER);
		textPassword.setColumns(10);
		textPassword.setBackground(Color.WHITE);
		textPassword.setBounds(498, 92, 322, 51);
		layeredPane_1.add(textPassword);
		
		JLabel lblPassword = new JLabel("Password:");
		lblPassword.setForeground(new Color(105, 105, 105));
		lblPassword.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblPassword.setBounds(329, 92, 191, 46);
		layeredPane_1.add(lblPassword);
		
		//registration-radio button
		JRadioButton registration = new JRadioButton("Registration");
		registration.setForeground(new Color(105, 105, 105));
		registration.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		registration.setBackground(SystemColor.inactiveCaption);
		registration.setBounds(41, 102, 155, 29);
		
		registration.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				 JRadioButton reg = (JRadioButton) e.getSource();
				 if(reg.isSelected()) {
					 textUsername.setEnabled(true);	//username
					 textPassword.setEnabled(true);	//password
					 //txtUrlServer.setText("http://test-tsa.ca.posta.rs/timestamp1");
					 comboBoxUrl.setSelectedIndex(1);
					 
				 }
				 else {
					 textUsername.setEnabled(false);	//username
					 textPassword.setEnabled(false);	//password
					 //txtUrlServer.setText("http://test-tsa.ca.posta.rs/timestamp");
					 comboBoxUrl.setSelectedIndex(0);
				 }
				 
			}
		});
		layeredPane_1.add(registration);
		
		//img-profile
		JLabel imgLblProfile = new JLabel("");
		imgLblProfile.setBounds(41, 16, 69, 64);
		Image imgProfile=new ImageIcon(this.getClass().getResource("/profile.png")).getImage();
		imgLblProfile.setIcon(new ImageIcon(imgProfile));
		layeredPane_1.add(imgLblProfile);
		
		JLayeredPane layeredPane_2 = new JLayeredPane();
		layeredPane_2.setOpaque(true);
		layeredPane_2.setForeground(Color.WHITE);
		layeredPane_2.setBackground(SystemColor.inactiveCaption);
		layeredPane_2.setBounds(15, 314, 859, 208);
		panel.add(layeredPane_2);
		
		//hash label
		JLabel lblHashAlgotihm = new JLabel("Hash algotihm:");
		lblHashAlgotihm.setForeground(new Color(105, 105, 105));
		lblHashAlgotihm.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblHashAlgotihm.setBounds(41, 16, 191, 46);
		layeredPane_2.add(lblHashAlgotihm);
		
		//nonce
		textNonce = new JTextField();
		textNonce.setHorizontalAlignment(SwingConstants.CENTER);
		textNonce.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 16));
		textNonce.setColumns(10);
		textNonce.setBackground(Color.WHITE);
		textNonce.setBounds(247, 66, 274, 51);
		textNonce.setText(Long.toString(controller.getRandom()));    
		layeredPane_2.add(textNonce);
		
		JLabel lblNonce = new JLabel("Nonce:");
		lblNonce.setForeground(new Color(105, 105, 105));
		lblNonce.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblNonce.setBounds(41, 67, 191, 46);
		layeredPane_2.add(lblNonce);
		
		//hash combo box
		JComboBox<String> comboBox = new JComboBox<String>();
		comboBox.setModel(new DefaultComboBoxModel(new String[] {"SHA_1", "SHA_224", "SHA_256", "SHA_384", "SHA_512"}));
		comboBox.setSelectedIndex(0);
		comboBox.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 18));
		comboBox.setOpaque(true);
		comboBox.getEditor().getEditorComponent().setBackground(UIManager.getColor("Button.disabledShadow"));
		comboBox.setBounds(248, 27, 106, 26);

		comboBox.setRenderer(new MyComboBoxRenderer());
		
		layeredPane_2.add(comboBox);
		
		//demanding cert radio button
		JRadioButton rdbtnDemandCertificate = new JRadioButton("<html>Demand TSA certificate in timestamp</html>");
		rdbtnDemandCertificate.setSelected(true);
		rdbtnDemandCertificate.setVerticalAlignment(SwingConstants.TOP);
		rdbtnDemandCertificate.setForeground(UIManager.getColor("Label.disabledForeground"));
		rdbtnDemandCertificate.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		rdbtnDemandCertificate.setBackground(SystemColor.inactiveCaption);
		rdbtnDemandCertificate.setBounds(549, 100, 288, 89);
		layeredPane_2.add(rdbtnDemandCertificate);
		
		//policy
		JLabel lblTsaPolicyOid = new JLabel("TSA Policy OID:");
		lblTsaPolicyOid.setForeground(new Color(105, 105, 105));
		lblTsaPolicyOid.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		lblTsaPolicyOid.setBounds(41, 139, 191, 46);
		layeredPane_2.add(lblTsaPolicyOid);
		
		textPolicyOid = new JTextField();
		textPolicyOid.setText(controller.getPolicy());
		textPolicyOid.setHorizontalAlignment(SwingConstants.CENTER);
		textPolicyOid.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 18));
		textPolicyOid.setColumns(10);
		textPolicyOid.setBackground(Color.WHITE);
		textPolicyOid.setBounds(247, 133, 274, 51);
		layeredPane_2.add(textPolicyOid);
		
		//img-key
		JLabel lblImgKey = new JLabel("");
		lblImgKey.setBounds(754, 30, 69, 58);
		
		Image imgKey=new ImageIcon(this.getClass().getResource("/key.png")).getImage();
		lblImgKey.setIcon(new ImageIcon(imgKey));
		layeredPane_2.add(lblImgKey);
	
		
		//layered panel za file
		JLayeredPane layeredPane_3 = new JLayeredPane();
		layeredPane_3.setOpaque(true);
		layeredPane_3.setForeground(new Color(128, 128, 128));
		layeredPane_3.setBackground(SystemColor.inactiveCaption);
		layeredPane_3.setBounds(15, 538, 859, 164);
		panel.add(layeredPane_3);
		
		//fileChooser
		JLabel lblSelectedFile = new JLabel("");
		lblSelectedFile.setForeground(SystemColor.textInactiveText);
		lblSelectedFile.setFont(new Font("Yu Gothic Medium", Font.PLAIN, 20));
		lblSelectedFile.setBounds(387, 20, 164, 41);
		layeredPane_3.add(lblSelectedFile);
		
		//Browse button
		JButton btnChooseFile = new JButton("Browse");
		btnChooseFile.setForeground(new Color(128, 128, 128));
		btnChooseFile.setBackground(UIManager.getColor("Button.highlight"));
		btnChooseFile.setFont(new Font("Yu Gothic Medium", Font.BOLD, 18));
		btnChooseFile.setBounds(215, 26, 157, 35);
		layeredPane_3.add(btnChooseFile);
		btnChooseFile.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
				int returnValue = jfc.showOpenDialog(null);
				if (returnValue == JFileChooser.APPROVE_OPTION) {
					selectedFile = jfc.getSelectedFile();
					if(selectedFile!=null)
						lblSelectedFile.setText(selectedFile.getName());
				}
				
			}
		});
		
		//file
		JLabel pdfDocLabel = new JLabel("PDF document:");
		pdfDocLabel.setForeground(SystemColor.textInactiveText);
		pdfDocLabel.setFont(new Font("Yu Gothic Medium", Font.BOLD, 20));
		pdfDocLabel.setBounds(41, 16, 342, 46);
		layeredPane_3.add(pdfDocLabel);
		
		JLabel labelFile = new JLabel("");
		labelFile.setBounds(754, 16, 69, 58);
		layeredPane_3.add(labelFile);
		Image imgFile=new ImageIcon(this.getClass().getResource("/file.png")).getImage();
		labelFile.setIcon(new ImageIcon(imgFile));
		
		//SUBMIT
		JButton submitBtn = new JButton(" SEND REQUEST");
		submitBtn.setBounds(296, 83, 280, 65);
		layeredPane_3.add(submitBtn);
		submitBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				boolean passed=true;
				if(registration.isSelected()) {
					//provere polja
					if(textUsername.getText().equals("") || textPassword.getText().equals("")) {
						JOptionPane.showMessageDialog(null, "When registration is selected, username and password must be entered.");
						passed=false;
					}
				}
				if(textNonce.getText().equals("") ||selectedFile==null) {
					JOptionPane.showMessageDialog(null, "Please enter all the required fields.");
					passed=false;
				}
				if(passed)
					try {
						controller.submit(comboBoxUrl.getSelectedItem().toString(), textUsername.getText(), textPassword.getText(), textNonce.getText(), 
								textPolicyOid.getText(), selectedFile.getAbsolutePath(),selectedFile.getName(), 
								rdbtnDemandCertificate.isSelected(), comboBox.getSelectedItem().toString(), registration.isSelected());
						System.out.println("Username i pass:	");
						System.out.println(textUsername.getText()+"  "+textPassword.getText());
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				
			}
		});
		Image imgTime=new ImageIcon(this.getClass().getResource("/stamp32.png")).getImage();
		submitBtn.setFont(new Font("Yu Gothic Medium", Font.BOLD, 22));
		submitBtn.setForeground(new Color(128, 128, 128));
		submitBtn.setBackground(UIManager.getColor("Button.highlight"));
		submitBtn.setOpaque(true);
		submitBtn.setIcon(new ImageIcon(imgTime));

		
	}
}
